import requests

def github_recon(query: str) -> str:
    """
    Recon a GitHub user, org, or search for a target term in public repos.
    Uses the unauthenticated GitHub API (60 req/hr limit).
    
    Input can be:
    - A username (e.g. torvalds)
    - An org (e.g. google)
    - A search term with prefix: search:target-company API key
    """
    if not query:
        return "Need a GitHub username, org name, or 'search:<query>'."

    query = query.strip()
    lines = [f"[GITHUB RECON] {query}\n"]
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "BuzzSINT-OSINT"
    }

    if query.lower().startswith("search:"):
        # Code search for secrets, leaks, etc.
        search_term = query[7:].strip()
        url = f"https://api.github.com/search/repositories?q={requests.utils.quote(search_term)}&sort=updated&per_page=20"
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            data = resp.json()

            if "message" in data:
                lines.append(f"  GitHub API: {data['message']}")
                if "rate limit" in data.get("message", "").lower():
                    lines.append("  Unauthenticated limit is 60 req/hr. Add a token for 5000/hr.")
                return "\n".join(lines)

            items = data.get("items", [])
            lines.append(f"  Repos matching '{search_term}': {data.get('total_count', 0):,} (showing {len(items)})\n")
            for repo in items:
                lines.append(f"  ● {repo['full_name']}")
                lines.append(f"    ★ {repo['stargazers_count']}  🍴 {repo['forks_count']}  Lang: {repo.get('language', 'N/A')}")
                lines.append(f"    {repo.get('description', 'No description')[:100]}")
                lines.append(f"    Updated: {repo['updated_at'][:10]}")
                lines.append(f"    URL: {repo['html_url']}")
                lines.append("")
        except Exception as e:
            lines.append(f"  Error: {e}")

    else:
        # User/org profile
        user_url = f"https://api.github.com/users/{query}"
        try:
            resp = requests.get(user_url, headers=headers, timeout=15)

            if resp.status_code == 404:
                lines.append(f"  User/org '{query}' not found on GitHub.")
                return "\n".join(lines)

            data = resp.json()
            lines += [
                f"  Login      : {data.get('login')}",
                f"  Name       : {data.get('name', 'N/A')}",
                f"  Type       : {data.get('type', 'N/A')}",
                f"  Bio        : {data.get('bio', 'N/A')}",
                f"  Company    : {data.get('company', 'N/A')}",
                f"  Location   : {data.get('location', 'N/A')}",
                f"  Email      : {data.get('email', 'N/A')}  ← exposed if they set it public",
                f"  Blog/Site  : {data.get('blog', 'N/A')}",
                f"  Twitter    : {data.get('twitter_username', 'N/A')}",
                f"  Public Repos : {data.get('public_repos', 0)}",
                f"  Followers  : {data.get('followers', 0)}",
                f"  Following  : {data.get('following', 0)}",
                f"  Created    : {data.get('created_at', 'N/A')[:10]}",
                f"  Profile    : {data.get('html_url', 'N/A')}",
            ]

            # Fetch repos
            repos_url = f"https://api.github.com/users/{query}/repos?sort=updated&per_page=20"
            repos_resp = requests.get(repos_url, headers=headers, timeout=10)
            repos = repos_resp.json()
            if isinstance(repos, list):
                lines.append(f"\n  Latest Repos ({len(repos)}):")
                for repo in repos[:15]:
                    lang = repo.get("language") or "?"
                    desc = (repo.get("description") or "")[:60]
                    lines.append(f"    {repo['name']:35s} [{lang:15s}] ★{repo['stargazers_count']:5} — {desc}")

        except Exception as e:
            lines.append(f"  Error: {e}")

    return "\n".join(lines)
