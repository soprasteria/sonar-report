export interface Param {
  key: string;
  desc: string;
  defaultValue: string;
}

export interface Rule {
  key: string;
  repo: string;
  name: string;
  createdAt: Date;
  updatedAt: Date;
  htmlDesc: string;
  severity: string;
  status: string;
  internalKey: string;
  isTemplate: boolean;
  tags: any[];
  sysTags: string[];
  lang: string;
  langName: string;
  scope: string;
  isExternal: boolean;
  type: string;
  params: Param[];
  mdNote: string;
  htmlNote: string;
  noteLogin: string;
  templateKey: string;
}

export interface Param2 {
  key: string;
  value: string;
}

export interface SquidMethodCyclomaticComplexity {
  qProfile: string;
  inherit: string;
  severity: string;
  params: Param2[];
}

export interface Param3 {
  key: string;
  value: string;
}

export interface Param4 {
  key: string;
  value: string;
}

export interface SquidClassCyclomaticComplexity {
  qProfile: string;
  inherit: string;
  severity: string;
  params: Param4[];
}

export interface Value {
  val: string;
  count: number;
}

export interface Facet {
  name: string;
  values: Value[];
}

export interface RulesResponse {
  total: number;
  p: number;
  ps: number;
  rules: Rule[];
  facets: Facet[];
}
