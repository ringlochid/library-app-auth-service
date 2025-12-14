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


class TestRBACConstants:
    """Test RBAC constants and data structures."""
    
    def test_roles_structure(self):
        """Test ROLES dictionary has expected structure."""
        assert "user" in ROLES
        assert "contributor" in ROLES
        assert "moderator" in ROLES
        assert "admin" in ROLES
        
        # Check that each role has a description
        assert isinstance(ROLES["user"], str)
        assert isinstance(ROLES["contributor"], str)
        assert isinstance(ROLES["moderator"], str)
        assert isinstance(ROLES["admin"], str)
    
    def test_scopes_structure(self):
        """Test SCOPES dictionary has expected structure."""
        # Check that key scopes exist
        assert "books:read" in SCOPES
        assert "books:create" in SCOPES
        assert "books:update" in SCOPES
        assert "books:delete" in SCOPES
        assert "authors:create" in SCOPES
        assert "admin:access" in SCOPES
    
    def test_role_scopes_mapping(self):
        """Test ROLE_SCOPES mapping is complete."""
        assert "user" in ROLE_SCOPES
        assert "contributor" in ROLE_SCOPES
        assert "moderator" in ROLE_SCOPES
        assert "admin" in ROLE_SCOPES
        
        # Check that admin has all scopes
        assert "admin:access" in ROLE_SCOPES["admin"]
        assert len(ROLE_SCOPES["admin"]) == len(SCOPES)


class TestGetScopesForRoles:
    """Test get_scopes_for_roles function."""
    
    def test_single_role_user(self):
        """Test getting scopes for user role only."""
        scopes = get_scopes_for_roles(["user"])
        assert "books:read" in scopes
        assert "reviews:create" in scopes
        assert "collections:create" in scopes
        assert "books:create" not in scopes
        assert "authors:create" not in scopes
    
    def test_single_role_contributor(self):
        """Test getting scopes for contributor role only."""
        scopes = get_scopes_for_roles(["contributor"])
        assert "books:read" in scopes
        assert "books:create" in scopes
        assert "books:update" in scopes
        assert "books:delete" in scopes
        assert "authors:create" in scopes
        assert "content:moderate" not in scopes
    
    def test_single_role_moderator(self):
        """Test getting scopes for moderator role only."""
        scopes = get_scopes_for_roles(["moderator"])
        assert "content:moderate" in scopes
        assert "reports:view" in scopes
        assert "users:blacklist" in scopes
        assert "admin:access" not in scopes
    
    def test_single_role_admin(self):
        """Test getting scopes for admin role only."""
        scopes = get_scopes_for_roles(["admin"])
        assert "admin:access" in scopes
        assert "users:manage" in scopes
        # Admin should have all scopes
        assert len(scopes) == len(SCOPES)
    
    def test_multiple_roles_user_contributor(self):
        """Test getting combined scopes for user + contributor."""
        scopes = get_scopes_for_roles(["user", "contributor"])
        # Should have both user and contributor scopes
        assert "books:read" in scopes
        assert "books:create" in scopes
        assert "books:update" in scopes
        assert "authors:create" in scopes
        assert "authors:update" in scopes
        # Should not have moderator scopes
        assert "content:moderate" not in scopes
    
    def test_multiple_roles_all(self):
        """Test getting combined scopes for all roles."""
        scopes = get_scopes_for_roles(["user", "contributor", "moderator", "admin"])
        # Should have scopes from all roles (admin has all, so all scopes present)
        assert "books:read" in scopes
        assert "books:create" in scopes
        assert "content:moderate" in scopes
        assert "admin:access" in scopes
        # Should have all scopes since admin is included
        assert len(scopes) == len(SCOPES)
    
    def test_empty_roles_list(self):
        """Test getting scopes for empty roles list."""
        scopes = get_scopes_for_roles([])
        assert scopes == []
    
    def test_unknown_role(self):
        """Test getting scopes for unknown role."""
        scopes = get_scopes_for_roles(["unknown_role"])
        assert scopes == []
    
    def test_deduplication(self):
        """Test that duplicate scopes are removed."""
        # If user had duplicate roles somehow
        scopes = get_scopes_for_roles(["user", "user"])
        # Should not have duplicates
        assert len(scopes) == len(set(scopes))


class TestCalculateUserRoles:
    """Test calculate_user_roles function."""
    
    def test_new_user_default_role(self):
        """Test that new user with trust_score=0 gets only 'user' role."""
        mock_user = Mock()
        mock_user.trust_score = 0
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert roles == ["user"]
    
    def test_contributor_promotion(self):
        """Test auto-promotion to contributor at trust_score >= 10."""
        mock_user = Mock()
        mock_user.trust_score = 10
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" not in roles
    
    def test_contributor_above_threshold(self):
        """Test contributor role with trust_score > 10."""
        mock_user = Mock()
        mock_user.trust_score = 25
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" not in roles
    
    def test_moderator_promotion(self):
        """Test auto-promotion to moderator at trust_score >= 50."""
        mock_user = Mock()
        mock_user.trust_score = 50
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" in roles
        assert "admin" not in roles
    
    def test_moderator_above_threshold(self):
        """Test moderator role with trust_score > 50."""
        mock_user = Mock()
        mock_user.trust_score = 100
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" in roles
        assert "admin" not in roles
    
    def test_admin_role(self):
        """Test that admin flag gives admin role."""
        mock_user = Mock()
        mock_user.trust_score = 5
        mock_user.is_admin = True
        
        roles = calculate_user_roles(mock_user)
        assert "admin" in roles
        # Should also have base roles
        assert "user" in roles
    
    def test_admin_with_high_trust(self):
        """Test admin with high trust score gets all roles."""
        mock_user = Mock()
        mock_user.trust_score = 100
        mock_user.is_admin = True
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" in roles
        assert "admin" in roles
    
    def test_negative_trust_score(self):
        """Test that negative trust_score is treated as 0."""
        mock_user = Mock()
        mock_user.trust_score = -5
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert roles == ["user"]
    
    def test_boundary_trust_score_9(self):
        """Test trust_score=9 does not get contributor."""
        mock_user = Mock()
        mock_user.trust_score = 9
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" not in roles
    
    def test_boundary_trust_score_49(self):
        """Test trust_score=49 does not get moderator."""
        mock_user = Mock()
        mock_user.trust_score = 49
        mock_user.is_admin = False
        
        roles = calculate_user_roles(mock_user)
        assert "user" in roles
        assert "contributor" in roles
        assert "moderator" not in roles
