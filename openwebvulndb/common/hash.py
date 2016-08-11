import hashlib
from os import walk
from os.path import join

from .models import Signature, VersionList
from .parallel import BackgroundRunner
from .version import VersionCompare
from .logs import logger
from .errors import ExecutionFailure


class RepositoryHasher:
    def __init__(self, *, storage, hasher=None, subversion=None, background_runner=None):
        self.storage = storage
        self.hasher = hasher or Hasher('SHA256')
        self.handlers = dict(subversion=subversion)
        self.background_runner = background_runner or BackgroundRunner(None)

    async def collect_for_version(self, workspace, version, *, prefix=""):
        await workspace.to_version(version)

        def collect():
            collector = HashCollector(path=workspace.workdir, hasher=self.hasher, prefix=prefix, lookup_version=version)
            return list(collector.collect())

        return await self.background_runner.run(collect)

    async def collect_for_workspace(self, key, workspace, *, prefix=""):
        version_list = await self.background_runner.run(self.get_version_list, key)
        try:
            repository_versions = set(await workspace.list_versions())
            stored_versions = {v.version for v in version_list.versions}
            required_versions = VersionCompare.sorted(repository_versions - stored_versions)

            for v in required_versions:
                signatures = await self.collect_for_version(workspace, v, prefix=prefix)
                desc = version_list.get_version(v, create_missing=True)
                desc.signatures = signatures
        except ExecutionFailure:
            logger.warn("A command failed to execute. Skipping the rest of the task, please try again later.")

        await self.background_runner.run(self.storage.write_versions, version_list)

    async def collect_from_meta(self, meta, prefix_pattern=""):
        try:
            for repo in meta.repositories:
                repo_handler = self.handlers.get(repo.type)
                if repo_handler is None:
                    continue

                with repo_handler.workspace(repository=repo.location) as workspace:
                    await workspace.prepare()

                    prefix = prefix_pattern.format(meta=meta)
                    await self.collect_for_workspace(meta.key, workspace, prefix=prefix)

                return True
        except ExecutionFailure:
            logger.warn("A command failed to execute. Skipping the rest of the task, please try again later.")

        return False

    def get_version_list(self, key):
        try:
            return self.storage.read_versions(key)
        except FileNotFoundError:
            return VersionList(producer="RepositoryHasher", key=key)


class HashCollector:

    def __init__(self, *, path, hasher, prefix="", lookup_version=None):
        self.path = path
        self.hasher = hasher
        self.prefix = prefix
        self.version_checker = VersionChecker(lookup_version)

    def collect(self):
        for path, dirs, files in walk(self.path):

            for file in files:
                full_path = join(path, file)
                relative = full_path[len(self.path):].strip("/")

                if relative[0] == "." or file[-4:] == ".php" or "/." in relative:
                    continue

                self.version_checker.reset()

                sig = Signature(path=join(self.prefix, relative), algo=self.hasher.algo)

                sig.hash = self.hasher.hash(full_path, chunk_cb=self.version_checker)
                sig.contains_version = self.version_checker.contains_version
                yield sig


class Hasher:
    def __init__(self, algo):
        self.algo = algo

    def hash(self, file_path, chunk_cb=lambda c: None):
        hash = hashlib.new(self.algo)
        with open(file_path, "rb") as fp:
            for chunk in iter(lambda: fp.read(4096), b""):
                hash.update(chunk)
                chunk_cb(chunk)

            return hash.hexdigest()


class VersionChecker:
    def __init__(self, version):
        self.version = version.encode('utf-8') if version is not None else version
        self.reset()

    def reset(self):
        self.contains_version = None

    def __call__(self, chunk):
        if self.version is not None and self.version in chunk:
            self.contains_version = True
