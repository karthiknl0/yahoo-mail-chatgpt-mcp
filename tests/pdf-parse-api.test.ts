import { describe, expect, it } from 'vitest';
import { PDFParse } from 'pdf-parse';

// Guards the pdf-parse v2 API used by read_email_attachments (src/yahoo.ts).
// v1 exported a function; v2 exports the PDFParse class, and calling it as a function throws.
function minimalPdf(text: string): Buffer {
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    '',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  const stream = `BT /F1 18 Tf 20 100 Td (${text}) Tj ET`;
  objs[3] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  let out = '%PDF-1.4\n';
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  offsets.forEach((o) => (out += `${String(o).padStart(10, '0')} 00000 n \n`));
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

describe('pdf-parse v2 API', () => {
  it('extracts text through PDFParse.getText()', async () => {
    const parser = new PDFParse({ data: new Uint8Array(minimalPdf('Hello Yahoo MCP')) });
    try {
      const result = await parser.getText();
      expect(result.text).toContain('Hello Yahoo MCP');
    } finally {
      await parser.destroy();
    }
  });
});
