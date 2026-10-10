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

export async function fetchDependabotAlert(owner, repo, alertNumber, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/dependabot/alerts/${encodeURIComponent(alertNumber)}`;
  const response = await fetch(url, {
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
      `GitHub API error fetching Dependabot alert #${alertNumber} for ${owner}/${repo}: ${response.status} ${response.statusText}${body ? ' - ' + body : ''}`
    );
  }

  const alert = await response.json();
  return { ...alert, repo: `${owner}/${repo}` };
}

function githubHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'periapsis',
  };
}

async function githubError(response, action) {
  const body = await response.text().catch(() => '');
  return new Error(`GitHub API error ${action}: ${response.status} ${response.statusText}${body ? ' - ' + body : ''}`);
}

export async function fetchDefaultBranch(owner, repo, token) {
  const response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: githubHeaders(token) });
  if (!response.ok) throw await githubError(response, `fetching ${owner}/${repo}`);
  const data = await response.json();
  return data.default_branch;
}

// Requires a token with Actions: write. workflow_dispatch input values must all be strings.
export async function dispatchWorkflow(owner, repo, workflow, ref, inputs, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${encodeURIComponent(workflow)}/dispatches`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { ...githubHeaders(token), 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref, inputs }),
  });
  if (!response.ok) throw await githubError(response, `dispatching ${workflow} on ${owner}/${repo}`);
}
