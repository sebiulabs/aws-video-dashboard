"""Tests for user_manager module."""

import pytest

from user_manager import (
    _validate_username,
    _validate_password,
    check_permission,
    create_user,
    get_users,
    get_user,
    get_user_by_username,
    authenticate,
    update_user,
    delete_user,
)


# ── _validate_username pure logic ────────────────────────────────────────────

class TestValidateUsername:
    def test_valid_admin(self):
        assert _validate_username("admin") is True

    def test_valid_user_with_underscores_and_digits(self):
        assert _validate_username("user_123") is True

    def test_too_short(self):
        assert _validate_username("ab") is False

    def test_too_long(self):
        assert _validate_username("a" * 31) is False

    def test_special_chars_rejected(self):
        assert _validate_username("admin@!") is False

    def test_exactly_three_chars_valid(self):
        assert _validate_username("abc") is True

    def test_exactly_thirty_chars_valid(self):
        assert _validate_username("a" * 30) is True


# ── _validate_password pure logic ────────────────────────────────────────────

class TestValidatePassword:
    def test_valid_password(self):
        assert _validate_password("Password1") is True

    def test_too_short(self):
        assert _validate_password("Pass1") is False

    def test_seven_chars_invalid(self):
        assert _validate_password("Passwrd") is False

    def test_no_number(self):
        assert _validate_password("abcdefgh") is False

    def test_no_letter(self):
        assert _validate_password("12345678") is False

    def test_eight_chars_with_both(self):
        assert _validate_password("abcdefg1") is True


# ── check_permission pure logic ──────────────────────────────────────────────

class TestCheckPermission:
    def test_admin_gte_admin(self):
        assert check_permission("admin", "admin") is True

    def test_admin_gte_operator(self):
        assert check_permission("admin", "operator") is True

    def test_admin_gte_viewer(self):
        assert check_permission("admin", "viewer") is True

    def test_operator_gte_operator(self):
        assert check_permission("operator", "operator") is True

    def test_operator_gte_viewer(self):
        assert check_permission("operator", "viewer") is True

    def test_operator_lt_admin(self):
        assert check_permission("operator", "admin") is False

    def test_viewer_gte_viewer(self):
        assert check_permission("viewer", "viewer") is True

    def test_viewer_lt_operator(self):
        assert check_permission("viewer", "operator") is False

    def test_unknown_role_lt_viewer(self):
        assert check_permission("unknown", "viewer") is False


# ── CRUD operations ──────────────────────────────────────────────────────────

class TestCreateUser:
    def test_success_returns_user_dict_without_password_hash(self, tmp_users_db):
        user = create_user("testuser", "Password1", role="viewer")
        assert isinstance(user, dict)
        assert "id" in user
        assert "username" in user
        assert user["username"] == "testuser"
        assert "password_hash" not in user

    def test_invalid_username_returns_none(self, tmp_users_db):
        result = create_user("ab", "Password1")
        assert result is None

    def test_invalid_password_returns_none(self, tmp_users_db):
        result = create_user("validuser", "short")
        assert result is None

    def test_invalid_role_returns_none(self, tmp_users_db):
        result = create_user("validuser", "Password1", role="superadmin")
        assert result is None

    def test_duplicate_username_returns_none(self, tmp_users_db):
        create_user("dupuser", "Password1")
        result = create_user("dupuser", "Password2")
        assert result is None


class TestGetUsers:
    def test_returns_empty_initially(self, tmp_users_db):
        result = get_users()
        assert result == []

    def test_returns_created_users(self, tmp_users_db):
        create_user("alice", "Password1", role="admin")
        create_user("bob", "Password2", role="viewer")
        result = get_users()
        assert len(result) == 2


class TestGetUser:
    def test_get_by_id(self, tmp_users_db):
        created = create_user("findme", "Password1")
        fetched = get_user(created["id"])
        assert fetched["username"] == "findme"

    def test_nonexistent_returns_none(self, tmp_users_db):
        result = get_user(9999)
        assert result is None


class TestGetUserByUsername:
    def test_returns_user_with_password_hash(self, tmp_users_db):
        create_user("hashuser", "Password1")
        user = get_user_by_username("hashuser")
        assert user is not None
        assert user["username"] == "hashuser"
        assert "password_hash" in user

    def test_nonexistent_returns_none(self, tmp_users_db):
        result = get_user_by_username("nope")
        assert result is None


# ── Authentication ───────────────────────────────────────────────────────────

class TestAuthenticate:
    def test_success_returns_user_dict(self, tmp_users_db):
        create_user("authuser", "Password1")
        result = authenticate("authuser", "Password1")
        assert result is not None
        assert result["username"] == "authuser"
        assert "password_hash" not in result

    def test_updates_last_login(self, tmp_users_db):
        create_user("loginuser", "Password1")
        result = authenticate("loginuser", "Password1")
        assert result["last_login"] is not None

    def test_wrong_password_returns_none(self, tmp_users_db):
        create_user("wrongpw", "Password1")
        result = authenticate("wrongpw", "WrongPassword1")
        assert result is None

    def test_nonexistent_user_returns_none(self, tmp_users_db):
        result = authenticate("ghost", "Password1")
        assert result is None


# ── Update user ──────────────────────────────────────────────────────────────

class TestUpdateUser:
    def test_changes_role(self, tmp_users_db):
        user = create_user("roleuser", "Password1", role="viewer")
        updated = update_user(user["id"], {"role": "operator"})
        assert updated["role"] == "operator"

    def test_changes_email(self, tmp_users_db):
        user = create_user("emailuser", "Password1")
        updated = update_user(user["id"], {"email": "test@example.com"})
        assert updated["email"] == "test@example.com"

    def test_changes_password(self, tmp_users_db):
        user = create_user("pwuser", "Password1")
        update_user(user["id"], {"password": "NewPassword2"})
        # Old password should no longer work
        result = authenticate("pwuser", "Password1")
        assert result is None
        # New password should work
        result = authenticate("pwuser", "NewPassword2")
        assert result is not None

    def test_invalid_role_returns_none(self, tmp_users_db):
        user = create_user("badrole", "Password1", role="viewer")
        result = update_user(user["id"], {"role": "superadmin"})
        assert result is None


# ── Delete user ──────────────────────────────────────────────────────────────

class TestDeleteUser:
    def test_success(self, tmp_users_db):
        user = create_user("delme", "Password1", role="viewer")
        result = delete_user(user["id"])
        assert result is True
        assert get_user(user["id"]) is None

    def test_delete_last_admin_blocked(self, tmp_users_db):
        admin = create_user("onlyadmin", "Password1", role="admin")
        result = delete_user(admin["id"])
        assert result is False

    def test_delete_admin_when_another_exists(self, tmp_users_db):
        admin1 = create_user("admin1", "Password1", role="admin")
        create_user("admin2", "Password2", role="admin")
        result = delete_user(admin1["id"])
        assert result is True

    def test_nonexistent_returns_false(self, tmp_users_db):
        result = delete_user(9999)
        assert result is False
