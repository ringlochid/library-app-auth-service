"""
Tests for RBAC (Role-Based Access Control) functionality - Jury System.
"""

import pytest
from unittest.mock import Mock
from app.rbac import (
    ROLES,
    SCOPES,
    ROLE_SCOPES,
    get_scopes_for_roles,
    calculate_user_roles,
)


# Helper function to create mock users with proper spec
def create_mock_user(
    is_blacklisted=False, trust_score=0, reputation_percentage=100.0, is_admin=False
):
    """Create a mock user with proper spec to avoid Mock truthy issues."""
    mock_user = Mock(
        spec=["is_blacklisted", "trust_score", "is_admin", "reputation_percentage"]
    )
    mock_user.is_blacklisted = is_blacklisted
    mock_user.trust_score = trust_score
    mock_user.reputation_percentage = reputation_percentage
    mock_user.is_admin = is_admin
    return mock_user


class TestRBACConstants:
    """Test RBAC constants and data structures."""

    def test_roles_structure(self):
        """Test ROLES dictionary has expected structure."""
        expected_roles = [
            "blacklisted",
            "user",
            "contributor",
            "trusted",
            "curator",
            "admin",
        ]
        for role in expected_roles:
            assert role in ROLES, f"Role '{role}' not found in ROLES"

        # Check that each role has a description
        for role, desc in ROLES.items():
            assert isinstance(desc, str), f"Role '{role}' description is not a string"

    def test_scopes_structure(self):
        """Test SCOPES dictionary has expected structure."""
        # Check that key scopes exist (using actual scope names)
        required_scopes = [
            "books:read",
            "books:draft",
            "books:update_own",
            "books:delete_own",
            "books:edit_public_meta",
            "books:publish_direct",
            "books:replace_file",
            "jury:view",
            "jury:vote",
            "jury:override",
            "authors:draft",
            "authors:update_own",
            "authors:delete_own",
            "collections:create",
            "reports:create",
            "users:ban",
            "content:takedown",
        ]
        for scope in required_scopes:
            assert scope in SCOPES, f"Scope '{scope}' not found in SCOPES"

    def test_role_scopes_mapping(self):
        """Test ROLE_SCOPES mapping is complete."""
        expected_roles = [
            "blacklisted",
            "user",
            "contributor",
            "trusted",
            "curator",
            "admin",
        ]
        for role in expected_roles:
            assert role in ROLE_SCOPES, f"Role '{role}' not in ROLE_SCOPES mapping"

        # Check that admin has all scopes
        admin_scopes = ROLE_SCOPES["admin"]
        assert len(admin_scopes) > 0, "Admin should have scopes"


class TestGetScopesForRoles:
    """Test get_scopes_for_roles function."""

    def test_blacklisted_role(self):
        """Test blacklisted user can only read."""
        scopes = get_scopes_for_roles(["blacklisted"])
        assert "books:read" in scopes
        assert "books:draft" not in scopes
        assert len(scopes) == 1

    def test_single_role_user(self):
        """Test getting scopes for user role."""
        scopes = get_scopes_for_roles(["user"])
        assert "books:read" in scopes
        assert "reviews:create" in scopes
        assert "books:draft" in scopes
        # Should NOT have jury powers yet
        assert "jury:view" not in scopes

    def test_single_role_contributor(self):
        """Test getting scopes for contributor role (jury member)."""
        scopes = get_scopes_for_roles(["contributor"])
        # Should have jury powers
        assert "jury:view" in scopes
        assert "jury:vote" in scopes
        # edit_public_meta moved to trusted role
        assert "books:edit_public_meta" not in scopes
        # Should NOT have curator powers
        assert "jury:override" not in scopes

    def test_single_role_trusted(self):
        """Test getting scopes for trusted role (bypass jury)."""
        scopes = get_scopes_for_roles(["trusted"])
        # Should have bypass powers
        assert "books:publish_direct" in scopes
        assert "books:replace_file" in scopes
        # Should NOT have curator powers
        assert "jury:override" not in scopes

    def test_single_role_curator(self):
        """Test getting scopes for curator role (sheriff)."""
        scopes = get_scopes_for_roles(["curator"])
        # Should have curator powers
        assert "jury:override" in scopes
        assert "users:ban" in scopes
        assert "content:takedown" in scopes

    def test_single_role_admin(self):
        """Test admin has all scopes."""
        scopes = get_scopes_for_roles(["admin"])
        # Admin should have all scopes from SCOPES dict
        assert len(scopes) == len(SCOPES)
        assert "jury:override" in scopes
        assert "books:read" in scopes

    def test_multiple_roles_deduplication(self):
        """Test that duplicate scopes are removed."""
        scopes = get_scopes_for_roles(["user", "user"])
        assert len(scopes) == len(set(scopes))

    def test_empty_roles_list(self):
        """Test getting scopes for empty roles list."""
        scopes = get_scopes_for_roles([])
        assert scopes == []

    def test_unknown_role(self):
        """Test getting scopes for unknown role."""
        scopes = get_scopes_for_roles(["unknown_role"])
        assert scopes == []


class TestCalculateUserRoles:
    """Test calculate_user_roles function with jury system."""

    def test_blacklisted_user_overrides_all(self):
        """Test that blacklisted users can ONLY have blacklisted role."""
        mock_user = create_mock_user(
            is_blacklisted=True,
            trust_score=100,
            is_admin=True,
            reputation_percentage=100.0,
        )
        roles = calculate_user_roles(mock_user)
        assert roles == ["blacklisted"]

    def test_new_user_default_role(self):
        """Test new user gets only 'user' role."""
        mock_user = create_mock_user()
        roles = calculate_user_roles(mock_user)
        assert roles == ["user"]

    def test_contributor_promotion_at_trust_10(self):
        """Test auto-promotion to contributor at trust_score >= 10."""
        mock_user = create_mock_user(trust_score=10)
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "trusted" not in roles

    def test_boundary_trust_score_9_no_contributor(self):
        """Test trust_score=9 does not get contributor role."""
        mock_user = create_mock_user(trust_score=9)
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" not in roles

    def test_trusted_requires_trust_50_and_reputation_80(self):
        """Test auto-promotion to trusted requires trust >= 50 AND reputation >= 80%."""
        # Only trust_score >= 50, reputation < 80 -> contributor only
        mock_user = create_mock_user(trust_score=50, reputation_percentage=70.0)
        roles = calculate_user_roles(mock_user)
        assert "contributor" in roles
        assert "trusted" not in roles

        # Both conditions met -> trusted role
        mock_user.reputation_percentage = 80.0
        roles = calculate_user_roles(mock_user)
        assert "trusted" in roles

    def test_curator_requires_trust_80_and_reputation_90(self):
        """Test auto-promotion to curator requires trust >= 80 AND reputation >= 90%."""
        # Only trust_score >= 80, reputation < 90 -> trusted only
        mock_user = create_mock_user(trust_score=80, reputation_percentage=85.0)
        roles = calculate_user_roles(mock_user)
        assert "trusted" in roles
        assert "curator" not in roles

        # Both conditions met -> curator role
        mock_user.reputation_percentage = 90.0
        roles = calculate_user_roles(mock_user)
        assert "curator" in roles

    def test_admin_manual_role(self):
        """Test that admin flag gives admin role."""
        mock_user = create_mock_user(trust_score=5, is_admin=True)
        roles = calculate_user_roles(mock_user)
        assert "admin" in roles
        assert "user" in roles

    def test_admin_with_high_trust(self):
        """Test admin with high trust gets all roles."""
        mock_user = create_mock_user(
            trust_score=100, reputation_percentage=100.0, is_admin=True
        )
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "trusted" in roles
        assert "curator" in roles
        assert "admin" in roles

    def test_negative_trust_score(self):
        """Test that negative trust_score is treated as 0."""
        mock_user = create_mock_user(trust_score=-10)
        roles = calculate_user_roles(mock_user)
        assert roles == ["user"]

    def test_progression_path_user_to_curator(self):
        """Test progression: user -> contributor -> trusted -> curator."""
        mock_user = create_mock_user()

        # Stage 1: User only
        mock_user.trust_score = 5
        roles = calculate_user_roles(mock_user)
        assert roles == ["user"]

        # Stage 2: Contributor
        mock_user.trust_score = 10
        roles = calculate_user_roles(mock_user)
        assert "contributor" in roles

        # Stage 3: Trusted
        mock_user.trust_score = 50
        mock_user.reputation_percentage = 80.0
        roles = calculate_user_roles(mock_user)
        assert "trusted" in roles

        # Stage 4: Curator
        mock_user.trust_score = 80
        mock_user.reputation_percentage = 90.0
        roles = calculate_user_roles(mock_user)
        assert "curator" in roles
