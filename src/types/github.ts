export interface GitHubWebhookPayload {
  action?: string;
  issue?: GitHubIssue;
  pull_request?: GitHubPullRequest;
  comment?: GitHubComment;
  check_suite?: GitHubCheckSuite;
  repository: GitHubRepository;
  sender: GitHubUser;
  installation?: {
    id: number;
    account: GitHubUser;
  };
}

export interface GitHubIssue {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed';
  user: GitHubUser;
  labels: GitHubLabel[];
  created_at: string;
  updated_at: string;
  html_url: string;
  pull_request?: {
    head?: {
      ref: string;
      sha: string;
    };
    base?: {
      ref: string;
    };
  };
}

export interface GitHubPullRequest {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed' | 'merged';
  user: GitHubUser;
  head: GitHubPullRequestHead;
  base: GitHubPullRequestBase;
  labels: GitHubLabel[];
  created_at: string;
  updated_at: string;
  html_url: string;
  merged: boolean;
  mergeable: boolean | null;
  draft: boolean;
  merged_at: string | null;
}

export interface GitHubPullRequestHead {
  ref: string;
  sha: string;
  repo: GitHubRepository | null;
}

export interface GitHubPullRequestBase {
  ref: string;
  sha: string;
  repo: GitHubRepository;
}

export interface GitHubComment {
  id: number;
  body: string;
  user: GitHubUser;
  created_at: string;
  updated_at: string;
  html_url: string;
}

export interface GitHubCheckSuite {
  id: number;
  head_branch: string | null;
  head_sha: string;
  status: 'queued' | 'in_progress' | 'completed' | 'pending' | 'waiting' | 'requested' | null;
  conclusion:
    | 'success'
    | 'failure'
    | 'neutral'
    | 'cancelled'
    | 'skipped'
    | 'timed_out'
    | 'action_required'
    | 'startup_failure'
    | 'stale'
    | null;
  app: GitHubApp | null;
  pull_requests: GitHubPullRequest[] | null;
  created_at: string | null;
  updated_at: string | null;
  latest_check_runs_count: number;
  [key: string]: unknown;
}

export interface GitHubApp {
  id: number;
  slug?: string;
  name: string;
  [key: string]: unknown;
}

export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  owner: GitHubUser;
  private: boolean;
  html_url: string;
  default_branch: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  type: 'User' | 'Bot' | 'Organization';
  html_url: string;
  email?: string;
  name?: string;
}

export interface GitHubLabel {
  id: number;
  name: string;
  color: string;
  description: string | null;
}

export interface GitHubCombinedStatus {
  state: string;
  total_count: number;
  statuses: GitHubStatus[];
  [key: string]: unknown;
}

export interface GitHubStatus {
  state: string;
  context: string;
  description: string | null;
  target_url: string | null;
  [key: string]: unknown;
}

export interface GitHubCheckSuitesResponse {
  total_count: number;
  check_suites: GitHubCheckSuite[];
}

export interface GitHubReview {
  id: number;
  user: GitHubUser;
  body: string | null;
  state: 'APPROVED' | 'CHANGES_REQUESTED' | 'COMMENTED' | 'DISMISSED' | 'PENDING';
  html_url: string;
  commit_id: string;
  submitted_at: string | null;
}

// API Request/Response Types
export interface CreateCommentRequest {
  repoOwner: string;
  repoName: string;
  issueNumber: number;
  body: string;
}

export interface CreateCommentResponse {
  id: number | string;
  body: string;
  created_at: string;
}

export interface AddLabelsRequest {
  repoOwner: string;
  repoName: string;
  issueNumber: number;
  labels: string[];
}

export interface ManagePRLabelsRequest {
  repoOwner: string;
  repoName: string;
  prNumber: number;
  labelsToAdd?: string[];
  labelsToRemove?: string[];
}

export interface CreateLabelRequest {
  name: string;
  color: string;
  description?: string;
}

export interface CreateRepositoryLabelsRequest {
  repoOwner: string;
  repoName: string;
  labels: CreateLabelRequest[];
}

export interface GetCombinedStatusRequest {
  repoOwner: string;
  repoName: string;
  ref: string;
}

export interface HasReviewedPRRequest {
  repoOwner: string;
  repoName: string;
  prNumber: number;
  commitSha: string;
}

export interface GetCheckSuitesRequest {
  repoOwner: string;
  repoName: string;
  ref: string;
}

// Validation Types
export interface ValidatedGitHubParams {
  repoOwner: string;
  repoName: string;
  issueNumber: number;
}
