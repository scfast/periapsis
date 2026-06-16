import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

export function detectRepo() {
  try {
    if (process.env.GITHUB_REPOSITORY) {
      return process.env.GITHUB_REPOSITORY;
    }
  } catch {
    // fall through
  }

  try {
    const remoteUrl = execSync('git remote get-url origin', { encoding: 'utf8' }).trim();

    // SSH: git@github.com:owner/repo.git
    const sshMatch = remoteUrl.match(/git@[^:]+:([^/]+\/[^/]+?)(?:\.git)?$/);
    if (sshMatch) {
      return sshMatch[1];
    }

    // HTTPS: https://github.com/owner/repo.git
    const httpsMatch = remoteUrl.match(/https?:\/\/[^/]+\/([^/]+\/[^/]+?)(?:\.git)?$/);
    if (httpsMatch) {
      return httpsMatch[1];
    }
  } catch {
    // fall through
  }

  return null;
}

function parseNextUrl(linkHeader) {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  return match ? match[1] : null;
}

export async function fetchDependabotAlerts(owner, repo, token, { state = 'open', perPage = 100 } = {}) {
  const alerts = [];
  const initial = new URL(`https://api.github.com/repos/${owner}/${repo}/dependabot/alerts`);
  initial.searchParams.set('state', state);
  initial.searchParams.set('per_page', String(perPage));
  let nextUrl = initial.toString();

  while (nextUrl) {
    const response = await fetch(nextUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'periapsis',
      },
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(
        `GitHub API error fetching Dependabot alerts for ${owner}/${repo}: ${response.status} ${response.statusText}${body ? ' - ' + body : ''}`
      );
    }

    const pageAlerts = await response.json();
    for (const alert of pageAlerts) {
      alerts.push({ ...alert, repo: `${owner}/${repo}` });
    }

    nextUrl = parseNextUrl(response.headers.get('link'));
  }

  return alerts;
}
