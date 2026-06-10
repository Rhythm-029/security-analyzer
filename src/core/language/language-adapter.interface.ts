import { RepositoryFileDescriptor, SourceFactSet } from "../domain/appsec.types";

export interface LanguageAdapter {
  readonly id: string;
  supports(file: RepositoryFileDescriptor): boolean;
  parse(file: RepositoryFileDescriptor, content: string): Promise<SourceFactSet>;
}
