from marshmallow import Schema, fields, validate, post_load, validates_schema, ValidationError
from .models import Meta, Repository, Vulnerability, VulnerabilityList, VersionRange, Reference
from .models import VersionList, VersionDefinition
from .serialize import serialize


class RepositorySchema(Schema):
    class Meta:
        ordered = True

    type = fields.String(required=True)
    location = fields.Url(required=True)

    @post_load
    def make(self, data):
        return Repository(**data)


class MetaSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    name = fields.String(required=False, allow_none=True)
    url = fields.Url(required=False, allow_none=True)
    repositories = fields.Nested(RepositorySchema, many=True, required=False)

    @post_load
    def make(self, data):
        return Meta(**data)


class ReferenceSchema(Schema):
    class Meta:
        ordered = True

    type = fields.String(required=True)
    id = fields.String(required=False)
    url = fields.String(required=False)

    @validates_schema
    def check_required_fields(self, data):
        if not data.get("id") and not data.get("url"):
            raise ValidationError("Either id or url is required.")

    @post_load
    def make(self, data):
        return Reference(**data)


class VersionRangeSchema(Schema):
    class Meta:
        ordered = True

    introduced_in = fields.String(required=False)
    fixed_in = fields.String(required=False)

    @validates_schema
    def check_required_fields(self, data):
        if not data.get("introduced_in") and not data.get("fixed_in"):
            raise ValidationError("Either introduced_in or fixed_in is required.")

    @post_load
    def make(self, data):
        return VersionRange(**data)


class VulnerabilitySchema(Schema):
    class Meta:
        ordered = True

    id = fields.String(required=True)
    title = fields.String(required=True)

    reported_type = fields.String(required=False)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)

    affected_versions = fields.Nested(VersionRangeSchema, many=True, required=False)
    references = fields.Nested(ReferenceSchema, many=True, required=False)

    @post_load
    def make(self, data):
        return Vulnerability(**data)


class VulnerabilityListSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    producer = fields.String(required=True)
    vulnerabilities = fields.Nested(VulnerabilitySchema, many=True, required=True)

    @post_load
    def make(self, data):
        return VulnerabilityList(**data)


class VersionDefinitionSchema(Schema):
    class Meta:
        ordered = True

    version = fields.String(required=True)
    signatures = fields.Dict(required=False)

    @post_load
    def make(self, data):
        return VersionDefinition(**data)


class VersionListSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    producer = fields.String(required=True)
    versions = fields.Nested(VersionDefinitionSchema, many=True, required=True)

    @post_load
    def make(self, data):
        return VersionList(**data)
