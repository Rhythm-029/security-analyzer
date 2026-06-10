import { RepositoryFileDescriptor } from "../domain/appsec.types";
import { LanguageAdapter } from "./language-adapter.interface";

export class LanguageRegistryService {
  private readonly adapters: LanguageAdapter[] = [];

  register(adapter: LanguageAdapter): void {
    this.adapters.push(adapter);
  }

  resolve(file: RepositoryFileDescriptor): LanguageAdapter | undefined {
    return this.adapters.find(adapter => adapter.supports(file));
  }
}
