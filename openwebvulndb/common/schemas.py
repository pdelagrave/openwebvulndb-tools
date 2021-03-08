# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from marshmallow import Schema, fields, post_load, validates_schema, ValidationError, EXCLUDE
from .models import Meta, Repository, Vulnerability, VulnerabilityList, VersionRange, Reference, FileList, File, \
    FileSignature, FileListGroup, VulnerabilityListGroup, VersionList, VersionDefinition, Signature, MetaList


class BaseSchema(Schema):
    class Meta:
        ordered = True
        unknown = EXCLUDE


class RepositorySchema(BaseSchema):
    type = fields.String(required=True)
    location = fields.Url(required=True)

    @post_load
    def make(self, data, many, partial):
        return Repository(**data)


class ReferenceSchema(BaseSchema):
    type = fields.String(required=True)
    id = fields.String(required=False)
    url = fields.String(required=False)

    @validates_schema
    def check_required_fields(self, data, many, partial):
        if not data.get("id") and not data.get("url"):
            raise ValidationError("Either id or url is required.")

    @post_load
    def make(self, data, many, partial):
        return Reference(**data)


class MetaSchema(BaseSchema):
    key = fields.String(required=True)
    name = fields.String(required=False, allow_none=True)
    cpe_names = fields.List(fields.String(), required=False)
    url = fields.Url(required=False, allow_none=True)
    is_popular = fields.Boolean(required=False, allow_none=True)
    repositories = fields.Nested(RepositorySchema, many=True, required=False)
    hints = fields.Nested(ReferenceSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return Meta(**data)


class MetaListSchema(BaseSchema):
    key = fields.String(required=True)
    metas = fields.Nested(MetaSchema, required=False, many=True)

    @post_load
    def make(self, data, many, partial):
        return MetaList(**data)


class VersionRangeSchema(BaseSchema):
    introduced_in = fields.String(required=False)
    fixed_in = fields.String(required=False)

    @validates_schema
    def check_required_fields(self, data, many, partial):
        if not data.get("introduced_in") and not data.get("fixed_in"):
            raise ValidationError("Either introduced_in or fixed_in is required.")

    @post_load
    def make(self, data, many, partial):
        return VersionRange(**data)


class VulnerabilitySchema(BaseSchema):
    id = fields.String(required=True)
    title = fields.String(required=True)
    cvss = fields.Float(required=False)
    description = fields.String(required=False)

    reported_type = fields.String(required=False)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)

    affected_versions = fields.Nested(VersionRangeSchema, many=True, required=False)
    unaffected_versions = fields.Nested(VersionRangeSchema, many=True, required=False)
    references = fields.Nested(ReferenceSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return Vulnerability(**data)


class VulnerabilityListSchema(BaseSchema):
    key = fields.String(required=True)
    producer = fields.String(required=True)
    copyright = fields.String(required=False)
    license = fields.String(required=False)
    vulnerabilities = fields.Nested(VulnerabilitySchema, many=True, required=True)

    @post_load
    def make(self, data, many, partial):
        return VulnerabilityList(**data)


class VulnerabilityListGroupSchema(BaseSchema):
    producer = fields.String(required=True)
    vulnerability_lists = fields.Nested(VulnerabilityListSchema, many=True, required=True)

    @post_load
    def make(self, data, many, partial):
        return VulnerabilityListGroup(**data)


class SignatureSchema(BaseSchema):
    path = fields.String(required=True)
    algo = fields.String(required=True)
    hash = fields.String(required=True)
    contains_version = fields.Boolean(required=False)

    @post_load
    def make(self, data, many, partial):
        return Signature(**data)


class VersionDefinitionSchema(BaseSchema):
    version = fields.String(required=True)
    signatures = fields.Nested(SignatureSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return VersionDefinition(**data)


class VersionListSchema(BaseSchema):
    key = fields.String(required=True)
    producer = fields.String(required=True)
    versions = fields.Nested(VersionDefinitionSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return VersionList(**data)


class FileSignatureSchema(BaseSchema):
    hash = fields.String(required=True)
    versions = fields.List(fields.String, required=False)

    @post_load
    def make(self, data, many, partial):
        return FileSignature(**data)


class FileSchema(BaseSchema):
    path = fields.String(required=True)
    signatures = fields.Nested(FileSignatureSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return File(**data)


class FileListSchema(BaseSchema):
    key = fields.String(required=True)
    producer = fields.String(required=True)
    hash_algo = fields.String(required=True)
    files = fields.Nested(FileSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return FileList(**data)


class FileListGroupSchema(BaseSchema):
    key = fields.String(required=True)
    producer = fields.String(required=True)
    file_lists = fields.Nested(FileListSchema, many=True, required=False)

    @post_load
    def make(self, data, many, partial):
        return FileListGroup(**data)
