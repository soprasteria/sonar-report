export interface Paging {
  pageIndex: number;
  pageSize: number;
  total: number;
}

export interface Hotspot {
  key: string;
  component: string;
  project: string;
  securityCategory: string;
  vulnerabilityProbability: string;
  status: string;
  line: number;
  message: string;
  assignee: string;
  author: string;
  creationDate: Date;
  updateDate: Date;
}

export interface Component {
  key: string;
  qualifier: string;
  name: string;
  longName: string;
  path: string;
}

export interface HostspotsResponse {
  paging: Paging;
  hotspots: Hotspot[];
  components: Component[];
}
