export interface Component {
  key: string;
  qualifier: string;
  name: string;
  longName: string;
  path: string;
}

export interface Project {
  key: string;
  qualifier: string;
  name: string;
  longName: string;
}

export interface Rule {
  key: string;
  name: string;
  securityCategory: string;
  vulnerabilityProbability: string;
}

export interface Diff {
  key: string;
  newValue: string;
  oldValue: string;
}

export interface Changelog {
  user: string;
  userName: string;
  creationDate: Date;
  diffs: Diff[];
  avatar: string;
  isUserActive: boolean;
}

export interface Comment {
  key: string;
  login: string;
  htmlText: string;
  markdown: string;
  createdAt: Date;
}

export interface User {
  login: string;
  name: string;
  active: boolean;
}

export interface HotspotResponse {
  key: string;
  component: Component;
  project: Project;
  rule: Rule;
  status: string;
  line: number;
  hash: string;
  message: string;
  assignee: string;
  author: string;
  creationDate: Date;
  updateDate: Date;
  changelog: Changelog[];
  comment: Comment[];
  users: User[];
  canChangeStatus: boolean;
}
