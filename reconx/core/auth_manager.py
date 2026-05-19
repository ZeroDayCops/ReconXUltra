#!/usr/bin/env python3
"""
ReconX Ultra X — Auth-Aware Hunting Manager
=============================================
Manages authentication sessions for crawling and testing.
Supports cookie sessions, bearer tokens, login replay,
header injection, and session profiles.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime

RECONX_ROOT = Path(os.environ.get("RECONX_ROOT",
    Path(__file__).resolve().parent.parent))
AUTH_DIR = RECONX_ROOT / "configs" / "auth_profiles"
AUTH_DIR.mkdir(parents=True, exist_ok=True)


class AuthProfile:
    """An authentication session profile."""
    def __init__(self, name: str, auth_type: str = "cookie"):
        self.name = name
        self.auth_type = auth_type  # cookie, bearer, basic, custom
        self.cookies: dict = {}
        self.headers: dict = {}
        self.bearer_token: str = ""
        self.login_url: str = ""
        self.login_data: dict = {}
        self.created = datetime.now().isoformat()
        self.last_used = ""

    def set_cookie(self, name: str, value: str):
        self.cookies[name] = value

    def set_bearer(self, token: str):
        self.bearer_token = token
        self.auth_type = "bearer"
        self.headers["Authorization"] = f"Bearer {token}"

    def set_header(self, name: str, value: str):
        self.headers[name] = value

    def get_httpx_flags(self) -> str:
        """Generate httpx command-line flags for auth."""
        flags = []
        for k, v in self.headers.items():
            flags.append(f'-H "{k}: {v}"')
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            flags.append(f'-H "Cookie: {cookie_str}"')
        return " ".join(flags)

    def get_katana_flags(self) -> str:
        """Generate katana flags for auth."""
        flags = []
        for k, v in self.headers.items():
            flags.append(f'-H "{k}: {v}"')
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            flags.append(f'-H "Cookie: {cookie_str}"')
        return " ".join(flags)

    def get_nuclei_flags(self) -> str:
        """Generate nuclei flags for auth."""
        flags = []
        for k, v in self.headers.items():
            flags.append(f'-H "{k}: {v}"')
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            flags.append(f'-H "Cookie: {cookie_str}"')
        return " ".join(flags)

    def get_ffuf_flags(self) -> str:
        """Generate ffuf flags for auth."""
        flags = []
        for k, v in self.headers.items():
            flags.append(f'-H "{k}: {v}"')
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            flags.append(f'-b "{cookie_str}"')
        return " ".join(flags)

    def get_curl_flags(self) -> str:
        """Generate curl flags for auth."""
        flags = []
        for k, v in self.headers.items():
            flags.append(f'-H "{k}: {v}"')
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            flags.append(f'-b "{cookie_str}"')
        return " ".join(flags)

    def save(self):
        """Save profile to disk."""
        data = {
            "name": self.name,
            "auth_type": self.auth_type,
            "cookies": self.cookies,
            "headers": self.headers,
            "bearer_token": self.bearer_token,
            "login_url": self.login_url,
            "login_data": self.login_data,
            "created": self.created,
            "last_used": self.last_used,
        }
        (AUTH_DIR / f"{self.name}.json").write_text(json.dumps(data, indent=2))

    @staticmethod
    def load(name: str) -> 'AuthProfile':
        """Load a profile from disk."""
        path = AUTH_DIR / f"{name}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        profile = AuthProfile(data["name"], data.get("auth_type", "cookie"))
        profile.cookies = data.get("cookies", {})
        profile.headers = data.get("headers", {})
        profile.bearer_token = data.get("bearer_token", "")
        profile.login_url = data.get("login_url", "")
        profile.login_data = data.get("login_data", {})
        profile.created = data.get("created", "")
        profile.last_used = data.get("last_used", "")
        return profile


class AuthManager:
    """Manages multiple auth profiles."""
    def __init__(self):
        self.profiles: dict[str, AuthProfile] = {}
        self.active_profile: str = ""
        self._load_profiles()

    def _load_profiles(self):
        """Load all saved profiles."""
        if not AUTH_DIR.exists():
            return
        for f in AUTH_DIR.glob("*.json"):
            profile = AuthProfile.load(f.stem)
            if profile:
                self.profiles[profile.name] = profile

    def create_profile(self, name: str, auth_type: str = "cookie") -> AuthProfile:
        """Create a new auth profile."""
        profile = AuthProfile(name, auth_type)
        self.profiles[name] = profile
        profile.save()
        return profile

    def set_active(self, name: str) -> bool:
        """Set the active auth profile."""
        if name in self.profiles:
            self.active_profile = name
            return True
        return False

    def get_active(self) -> AuthProfile:
        """Get the currently active profile."""
        if self.active_profile:
            return self.profiles.get(self.active_profile)
        return None

    def list_profiles(self) -> list:
        """List all profiles."""
        return [{"name": p.name, "type": p.auth_type,
                 "active": p.name == self.active_profile,
                 "created": p.created}
                for p in self.profiles.values()]

    def export_env(self) -> dict:
        """Export active profile as environment variables for shell scripts."""
        profile = self.get_active()
        if not profile:
            return {}
        return {
            "RECONX_AUTH_HTTPX": profile.get_httpx_flags(),
            "RECONX_AUTH_KATANA": profile.get_katana_flags(),
            "RECONX_AUTH_NUCLEI": profile.get_nuclei_flags(),
            "RECONX_AUTH_FFUF": profile.get_ffuf_flags(),
            "RECONX_AUTH_CURL": profile.get_curl_flags(),
            "RECONX_AUTH_PROFILE": profile.name,
            "RECONX_AUTH_TYPE": profile.auth_type,
        }


if __name__ == "__main__":
    mgr = AuthManager()
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "create" and len(sys.argv) > 2:
            name = sys.argv[2]
            auth_type = sys.argv[3] if len(sys.argv) > 3 else "cookie"
            p = mgr.create_profile(name, auth_type)
            print(f"  ✅ Profile created: {name} ({auth_type})")
            print(f"  📁 Edit: {AUTH_DIR}/{name}.json")
        elif cmd == "list":
            profiles = mgr.list_profiles()
            print(f"\n  🔐 Auth Profiles ({len(profiles)}):")
            for p in profiles:
                active = " ← ACTIVE" if p["active"] else ""
                print(f"    {'🟢' if p['active'] else '⚪'} "
                      f"{p['name']} ({p['type']}){active}")
        elif cmd == "export" and len(sys.argv) > 2:
            mgr.set_active(sys.argv[2])
            env = mgr.export_env()
            for k, v in env.items():
                print(f"export {k}='{v}'")
        else:
            print("Usage: auth_manager.py [create|list|export] [name] [type]")
    else:
        profiles = mgr.list_profiles()
        print(f"  🔐 {len(profiles)} auth profiles available")
