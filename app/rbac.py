"""
Role-Based Access Control utilities.
"""

from typing import List
from app.models import User


# Role definitions
ROLES = {
    "blacklisted": "Read-only access, cannot interact (manual enforcement)",
    "user": "Regular reader (default)",
    "contributor": "Can create/manage books and authors (auto at trust_score >= 10)",
    "trusted": "Bypass queue, weighted voting (auto at trust_score >= 50 AND reputation >= 80%)",
    "curator": "Instant approve/reject power (auto at trust_score >= 80 AND reputation >= 90%)",
    "admin": "System administration (manual only)",
}


# Scope definitions
SCOPES = {
    # --- LEVEL 1: CONSUMER ---
    "books:read": "Read published books",
    "reviews:create": "Post reviews on published books",
    # --- LEVEL 2: DRAFTING (Standard User) ---
    "books:draft": "Submit a book to the Pending Queue (Not public)",
    "books:update_own": "Edit metadata/files of own pending/published books",
    "books:delete_own": "Soft-delete own uploads",
    "authors:draft": "Submit author profile to Pending Queue",
    "authors:update_own": "Edit own author profiles",
    "authors:delete_own": "Delete own author profiles",
    "collections:create": "Create personal collections",
    "collections:update_own": "Edit own collections",
    "collections:delete_own": "Delete own collections",
    # --- LEVEL 3: WIKI & JURY (Contributor) ---
    "jury:view": "Access the Review Queue",
    "jury:vote": "Cast weighted vote on pending content (+1 for contributor)",
    "reports:create": "Flag content for removal",
    # --- LEVEL 4: TRUSTED PRIVILEGES ---
    # CHANGE: move edit_public_meta to trusted roles
    "books:edit_public_meta": "Edit title/tags/desc of ANY book (Wiki Mode)",
    "authors:edit_public_meta": "Edit any author metadata (Wiki Mode)",
    # Publish direct
    "books:publish_direct": "Uploads go LIVE immediately (Bypass Jury)",
    "books:replace_file": "Replace the PDF/EPUB file of ANY book (Version Control)",
    "authors:publish_direct": "Author profiles go live immediately",
    # ADD collections:publish_direct to trusted roles
    "collections:publish_direct": "Collections go live immediately",
    # CHANGE: Move collections:manage_any to trusted roles
    "collections:manage_any": "Curate any collection",
    "jury:vote_weighted": "Cast +5 weighted vote (Trusted users)",
    # --- LEVEL 5: CURATION & ENFORCEMENT ---
    "jury:override": "Instant Approve/Reject power (Curator override)",
    "users:ban": "Ban malicious users",
    "content:takedown": "Hard removal (DMCA/Illegal content)",
    # --- ADMIN ---
    "system:access": "Access internal dashboards",
}

# Role to scopes mapping
ROLE_SCOPES = {
    # Unverified users - can only manage their own profile
    "unverified": ["books:read"],
    # The "Blacklisted" - Read only, no interaction.
    "blacklisted": ["books:read"],
    # The "Newbie" - Can submit drafts to pending queue.
    # Default role for new users (Trust Score starts at 0).
    "user": [
        "books:read",
        "reviews:create",
        "books:draft",
        "books:update_own",
        "books:delete_own",
        "authors:draft",
        "authors:update_own",
        "authors:delete_own",
        "collections:create",
        "collections:update_own",
        "collections:delete_own",
        "reports:create",
    ],
    # The "Citizen" - Jury duty + wiki editing power.
    # Requirement: Trust Score >= 10.
    "contributor": [
        # Inherits User
        "books:read",
        "reviews:create",
        "books:draft",
        "books:update_own",
        "books:delete_own",
        "authors:draft",
        "authors:update_own",
        "authors:delete_own",
        "collections:create",
        "collections:update_own",
        "collections:delete_own",
        "reports:create",
        # New Powers
        "jury:view",  # Access review queue
        "jury:vote",  # Vote weight = +1
    ],
    # The "Veteran" - Trusted fast-track.
    # Requirement: Trust Score >= 50 AND Reputation >= 80%.
    "trusted": [
        # Inherits Contributor
        "books:read",
        "reviews:create",
        "books:draft",
        "books:update_own",
        "books:delete_own",
        "authors:draft",
        "authors:update_own",
        "authors:delete_own",
        "collections:create",
        "collections:update_own",
        "collections:delete_own",
        "reports:create",
        "jury:view",
        "jury:vote",
        # Changed
        # New Powers
        "books:edit_public_meta",  # Wiki editing
        "authors:edit_public_meta",  # Wiki editing for authors
        "collections:manage_any",  # Curate featured collections
        "collections:publish_direct",  # Collections bypass queue
        "books:publish_direct",  # Bypass queue
        "books:replace_file",  # Fix broken files
        "authors:publish_direct",  # Authors bypass queue
        "jury:vote_weighted",  # Vote weight = +5
    ],
    # The "Sheriff" - Instant justice powers.
    # Requirement: Trust Score >= 80 AND Reputation >= 90%.
    "curator": [
        # Inherits Trusted
        "books:read",
        "reviews:create",
        "books:draft",
        "books:update_own",
        "books:delete_own",
        "authors:draft",
        "authors:update_own",
        "authors:delete_own",
        "collections:create",
        "collections:update_own",
        "collections:delete_own",
        "collections:manage_any",  # Curate featured collections
        "collections:publish_direct",  # Collections bypass queue
        "reports:create",
        "books:edit_public_meta",
        "authors:edit_public_meta",
        "jury:view",
        "jury:vote",
        "books:publish_direct",
        "books:replace_file",
        "authors:publish_direct",
        "jury:vote_weighted",
        # New Powers
        "jury:override",  # Instant approve/reject
        "users:ban",  # Ban trolls
        "content:takedown",  # DMCA/illegal removal
    ],
    # The "Owner" - Full system access.
    "admin": list(SCOPES.keys()),  # All scopes
}


def get_scopes_for_roles(roles: List[str]) -> List[str]:
    """
    Get unique list of scopes for given roles.

    Args:
        roles: List of role names

    Returns:
        Deduplicated list of scopes
    """
    scopes = set()
    for role in roles:
        if role in ROLE_SCOPES:
            scopes.update(ROLE_SCOPES[role])
    return sorted(list(scopes))


def calculate_user_roles(user: User) -> List[str]:
    """
    Calculate roles based on user's trust_score, reputation_percentage, and flags.

    Auto-promotion rules (Jury System):
    - Default: user (trust_score = 0)
    - trust_score >= 10: contributor (Jury voter, +1 vote weight)
    - trust_score >= 50 AND reputation >= 80%: trusted (Bypass queue, +5 vote weight)
    - trust_score >= 80 AND reputation >= 90%: curator (Instant approve/reject)
    - is_admin: admin (manual only, full access)
    - is_blacklisted: blacklisted (read-only, overrides everything)
    - is_locked: temporarily downgraded to user (no contributor+ privileges)

    Args:
        user: User model instance

    Returns:
        List of role names
    """
    # Blacklist check overrides everything
    if hasattr(user, "is_blacklisted") and user.is_blacklisted:
        return ["blacklisted"]

    # Unverified users get restricted role (can only manage profile)
    if hasattr(user, "email_verified_at") and user.email_verified_at is None:
        return ["unverified"]

    # Locked users are temporarily downgraded to base "user" role
    if hasattr(user, "is_locked") and user.is_locked:
        return ["user"]

    roles = ["user"]  # Base role

    # Auto-promote based on trust_score and reputation
    if user.trust_score >= 10:
        roles.append("contributor")

    if user.trust_score >= 50 and user.reputation_percentage >= 80.0:
        roles.append("trusted")

    if user.trust_score >= 80 and user.reputation_percentage >= 90.0:
        roles.append("curator")

    # Admin is always manual
    if user.is_admin:
        roles.append("admin")

    return roles
