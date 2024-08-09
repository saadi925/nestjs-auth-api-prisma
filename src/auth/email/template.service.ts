import { Injectable } from "@nestjs/common";
import * as fs from "fs";
import * as path from "path";
import { promisify } from "util";

type TemplateFileName = "verification" | "reset-password";
const readFileAsync = promisify(fs.readFile);
@Injectable()
export class TemplateService {
   async getTemplate(fileName: `${TemplateFileName}.html`, replacements: { [key: string]: string }): Promise<string> {
    const filePath = path.join(process.cwd(), "src/auth/email/templates", fileName);
    let template = await readFileAsync(filePath, "utf-8");

    for (const [key, value] of Object.entries(replacements)) {
      template = template.replace(new RegExp(`{{${key}}}`, "g"), value);
    }

    return template;
  }
}
