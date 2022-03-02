export interface Paging {
  pageIndex: number;
  pageSize: number;
  total: number;
}

export interface Comment {
  key: string;
  login: string;
  htmlText: string;
  markdown: string;
  updatable: boolean;
  createdAt: Date;
}

export interface TextRange {
  startLine: number;
  endLine: number;
  startOffset: number;
  endOffset: number;
}

export interface TextRange2 {
  startLine: number;
  endLine: number;
  startOffset: number;
  endOffset: number;
}

export interface Location {
  textRange: TextRange2;
  msg: string;
}

export interface Flow {
  locations: Location[];
}

export interface Issue {
  key: string;
  component: string;
  project: string;
  rule: string;
  status: string;
  resolution: string;
  severity: string;
  message: string;
  line: number;
  hash: string;
  author: string;
  effort: string;
  creationDate: Date;
  updateDate: Date;
  tags: string[];
  type: string;
  comments: Comment[];
  transitions: string[];
  actions: string[];
  textRange: TextRange;
  flows: Flow[];
}

export interface Component {
  key: string;
  enabled: boolean;
  qualifier: string;
  name: string;
  longName: string;
  path: string;
}

export interface Rule {
  key: string;
  name: string;
  status: string;
  lang: string;
  langName: string;
}

export interface User {
  login: string;
  name: string;
  active: boolean;
  avatar: string;
}

export interface IssuesResponse {
  paging: Paging;
  issues: Issue[];
  components: Component[];
  rules: Rule[];
  users: User[];
}
