export interface FieldValue {
  boolean: string;
  text: string;
}

export interface Setting {
  key: string;
  value: string;
  inherited: boolean;
  values: string[];
  fieldValues: FieldValue[];
}

export interface SettingsResponse {
  settings: Setting[];
}
