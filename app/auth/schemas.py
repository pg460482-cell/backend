from marshmallow import Schema, fields, validates, ValidationError
import re


# ================= SHARED HELPER =================

def validate_password_strength(value):
    """Reusable password validator — schemas mein duplicate nahi hoga"""
    if len(value) < 8:
        raise ValidationError("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", value):
        raise ValidationError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", value):
        raise ValidationError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", value):
        raise ValidationError("Password must contain at least one number")
    if not re.search(r"[@!$%*?&]", value):
        raise ValidationError(
            "Password must contain at least one special character (@!$%*?&)"
        )


# ================= SCHEMAS =================

class RegisterSchema(Schema):
    username = fields.Str(required=True)
    email    = fields.Email(required=True)
    password = fields.Str(required=True)

    @validates("username")
    def validate_username(self, value):
        if len(value) < 3 or len(value) > 20:
            raise ValidationError("Username must be between 3 and 20 characters")
        if not re.match(r"^[A-Za-z][A-Za-z0-9_.]*$", value):
            raise ValidationError(
                "Username must start with a letter and only contain "
                "letters, numbers, dots, and underscores"
            )

    @validates("password")
    def validate_password(self, value):
        validate_password_strength(value)


class LoginSchema(Schema):
    email    = fields.Email(required=True)
    password = fields.Str(required=True)


class ForgotPasswordSchema(Schema):
    email = fields.Email(required=True)


class ResetPasswordSchema(Schema):
    token    = fields.Str(required=True)
    password = fields.Str(required=True)

    @validates("password")
    def validate_password(self, value):
        validate_password_strength(value)


class UpdateProfileSchema(Schema):
    username = fields.Str()
    email    = fields.Email()

    @validates("username")
    def validate_username(self, value):
        if value and (len(value) < 3 or len(value) > 20):
            raise ValidationError("Username must be between 3 and 20 characters")


class ChangePasswordSchema(Schema):
    current_password = fields.Str(required=True)
    new_password     = fields.Str(required=True)

    @validates("new_password")
    def validate_new_password(self, value):
        validate_password_strength(value)
