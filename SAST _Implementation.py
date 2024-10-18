import os
import subprocess
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from datetime import datetime

def scan_code(directory):
    """Jalankan Semgrep pada direktori yang ditentukan."""
    command = ["semgrep", "--config", "auto", "--json", directory]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode('utf-8').strip()
    if error_message:
        print("Progress Scan:\n",error_message)

    return result.stdout.decode('utf-8')

def parse_results(output):
    """Parse output JSON dari Semgrep."""
    try:
        json_output = json.loads(output)
        # Menghapus tampilan output JSON untuk debugging
        # print("Output JSON:", json_output)  
        return json_output.get('results', [])
    except json.JSONDecodeError:
        print("Error decoding JSON from Semgrep output")
        return []

def write_pdf(vulnerabilities, output_file):
    """Tulis kerentanan ke file PDF dengan format yang lebih baik."""
    pdf = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Header
    header = Paragraph("Static Application Security Testing and Automation", styles['Title'])
    story.append(header)
    story.append(Spacer(1, 12))

    # Tanggal
    date_str = f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(date_str, styles['Normal']))
    story.append(Spacer(1, 12))

    # Jumlah kerentanan
    if vulnerabilities:
        summary = f"Ditemukan {len(vulnerabilities)} kerentanan."
    else:
        summary = "Tidak ada kerentanan ditemukan."
    
    story.append(Paragraph(summary, styles['Normal']))
    story.append(Spacer(1, 12))

    # Detail kerentanan
    for vuln in vulnerabilities:
        file_info = f"<b>File:</b> {vuln['path']}"
        line_info = f"<b>Baris:</b> {vuln['start']['line']} - {vuln['end']['line']}"
        message_info = f"<b>Pesan:</b> {vuln.get('extra', {}).get('message', 'Tidak ada pesan')}"

        story.append(Paragraph(file_info, styles['Normal']))
        story.append(Paragraph(line_info, styles['Normal']))
        story.append(Paragraph(message_info, styles['Normal']))
        story.append(Spacer(1, 12))  # Jarak antar kerentanan

    # Footer (opsional)
    footer = Paragraph("Laporan ini dihasilkan oleh Bandit open source dan automation yang dimodifikasi oleh Benni Tampubolon", styles['Normal'])
    story.append(Spacer(1, 12))
    story.append(footer)

    pdf.build(story)

def main():
    code_directory = input("Masukkan direktori kode sumber yang akan dipindai: ")
    output_pdf = input("Masukkan nama file PDF output (misalnya, hasil.pdf): ")

    # Jalankan pemindaian
    print("Memindai kode...")
    output = scan_code(code_directory)

    # Parse hasil
    vulnerabilities = parse_results(output)

    # Buat laporan PDF
    write_pdf(vulnerabilities, output_pdf)
    print(f"Laporan disimpan sebagai {output_pdf}.")

if __name__ == "__main__":
    main()

# Copyright Benni Hasahatan Tampubolon