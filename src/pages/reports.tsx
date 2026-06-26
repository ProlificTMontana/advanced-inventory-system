import { useState } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useItems } from '../hooks/use-items';
import { FileSpreadsheet, FileText, CheckCircle2, Loader2 } from 'lucide-react';
import ExcelJS from 'exceljs';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';

export default function Reports() {
  const { items, isLoading } = useItems();
  const [selectedType, setSelectedType] = useState('low_stock');
  const [isExporting, setIsExporting] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  const reportData = items.filter(item => {
    if (selectedType === 'low_stock') return item.quantity <= item.min_stock;
    return true;
  });

  const exportToExcel = async () => {
    setIsExporting(true);
    try {
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Inventory Report');

      worksheet.columns = [
        { header: 'Item Name', key: 'name', width: 30 },
        { header: 'SKU', key: 'sku', width: 15 },
        { header: 'Quantity', key: 'quantity', width: 12 },
        { header: 'Min Stock', key: 'min_stock', width: 12 },
        { header: 'Price', key: 'price', width: 12 },
        { header: 'Location', key: 'location', width: 15 },
        { header: 'Category', key: 'category', width: 20 },
      ];

      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' },
      };

      reportData.forEach((item) => {
        worksheet.addRow({
          name: item.name,
          sku: item.sku,
          quantity: item.quantity,
          min_stock: item.min_stock,
          price: item.price,
          location: item.location,
          category: item.categories?.name || 'Uncategorized',
        });
      });

      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `inventory-report-${selectedType}-${new Date().toISOString().split('T')[0]}.xlsx`;
      a.click();
      window.URL.revokeObjectURL(url);

      setSuccessMsg('Excel report exported successfully');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch (error) {
      console.error('Excel export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const exportToPDF = async () => {
    setIsExporting(true);
    try {
      const pdfDoc = await PDFDocument.create();
      const page = pdfDoc.addPage();
      const { width, height } = page.getSize();
      const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
      const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

      // Title
      page.drawText('Inventory Report', {
        x: 50,
        y: height - 50,
        size: 20,
        font: boldFont,
        color: rgb(0, 0, 0),
      });

      page.drawText(`Report Type: ${selectedType === 'low_stock' ? 'Low Stock' : 'Full Inventory'}`, {
        x: 50,
        y: height - 80,
        size: 12,
        font: font,
        color: rgb(0.3, 0.3, 0.3),
      });

      page.drawText(`Generated: ${new Date().toLocaleDateString()}`, {
        x: 50,
        y: height - 100,
        size: 10,
        font: font,
        color: rgb(0.5, 0.5, 0.5),
      });

      // Table headers
      const headers = ['Item Name', 'SKU', 'Qty', 'Min', 'Price', 'Location'];
      const headerY = height - 130;
      headers.forEach((header, i) => {
        page.drawText(header, {
          x: 50 + i * 80,
          y: headerY,
          size: 10,
          font: boldFont,
          color: rgb(0, 0, 0),
        });
      });

      // Table data
      let y = headerY - 20;
      reportData.slice(0, 20).forEach((item) => {
        page.drawText(item.name.substring(0, 15), { x: 50, y, size: 9, font, color: rgb(0, 0, 0) });
        page.drawText(item.sku, { x: 130, y, size: 9, font, color: rgb(0, 0, 0) });
        page.drawText(item.quantity.toString(), { x: 210, y, size: 9, font, color: rgb(0, 0, 0) });
        page.drawText(item.min_stock.toString(), { x: 290, y, size: 9, font, color: rgb(0, 0, 0) });
        page.drawText(`$${item.price.toFixed(2)}`, { x: 370, y, size: 9, font, color: rgb(0, 0, 0) });
        page.drawText(item.location, { x: 450, y, size: 9, font, color: rgb(0, 0, 0) });
        y -= 15;
      });

      const pdfBytes = await pdfDoc.save();
      const blob = new Blob([pdfBytes as any], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `inventory-report-${selectedType}-${new Date().toISOString().split('T')[0]}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);

      setSuccessMsg('PDF report exported successfully');
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch (error) {
      console.error('PDF export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExport = (format: 'Excel' | 'PDF') => {
    if (format === 'Excel') {
      exportToExcel();
    } else {
      exportToPDF();
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Report Compiler Engine</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">Generate, evaluate, and export standardized structural data configurations.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="p-4 space-y-4 md:col-span-1">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Configuration Query Context</h3>
          <div className="space-y-2">
            {[
              { id: 'low_stock', label: 'Threshold Breaches (Low Stock)' },
              { id: 'full_inventory', label: 'Comprehensive Master Ledger' },
            ].map(type => (
              <button
                key={type.id}
                onClick={() => setSelectedType(type.id)}
                className={`w-full text-left text-sm px-3 py-2.5 rounded-lg font-medium transition-colors border ${
                  selectedType === type.id 
                    ? 'bg-blue-50/60 text-blue-600 border-blue-200 dark:bg-blue-950/40 dark:border-blue-800 dark:text-blue-400' 
                    : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:border-slate-800 dark:text-slate-400 dark:hover:bg-slate-800/40'
                }`}
              >
                {type.label}
              </button>
            ))}
          </div>

          <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <Button className="w-full flex items-center justify-center gap-2" variant="secondary" disabled={isExporting} onClick={() => handleExport('Excel')}>
              <FileSpreadsheet className="w-4 h-4 text-emerald-600" /> Export Excel Asset
            </Button>
            <Button className="w-full flex items-center justify-center gap-2" variant="secondary" disabled={isExporting} onClick={() => handleExport('PDF')}>
              <FileText className="w-4 h-4 text-rose-500" /> Export Structured PDF
            </Button>
          </div>
        </Card>

        <Card className="p-4 md:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3 mb-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Compiled Manifest Target Compilation</h3>
            <span className="text-xs text-slate-500">{reportData.length} records resolved</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
            </div>
          ) : (
            <>
              {successMsg && (
                <div className="mb-4 p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 text-emerald-800 dark:text-emerald-400 text-xs rounded-lg flex items-start gap-2.5 animate-in fade-in duration-200">
                  <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />
                  <span>{successMsg}</span>
                </div>
              )}

              <div className="overflow-hidden border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-slate-400 font-medium">
                <tr>
                  <th className="p-2.5">SKU / Item Identifier</th>
                  <th className="p-2.5 text-right">Available Volume</th>
                  <th className="p-2.5 text-right">Floor Spec</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-600 dark:text-slate-300">
                {reportData.map((item) => (
                  <tr key={item.id}>
                    <td className="p-2.5 font-medium text-slate-900 dark:text-white">{item.name} <span className="font-mono text-[10px] text-slate-400 block">{item.sku}</span></td>
                    <td className="p-2.5 text-right font-mono font-semibold">{item.quantity}</td>
                    <td className="p-2.5 text-right font-mono text-slate-400">{item.min_stock}</td>
                  </tr>
                ))}
              </tbody>
            </table>
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
