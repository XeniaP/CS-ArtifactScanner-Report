import sys
import pandas as pd
from pandas import ExcelWriter
import json
import os

def ExportExcel(df, filename, sheetname):
    if(os.path.exists(f'{filename}.xlsx')):
        with ExcelWriter(f'{filename}.xlsx', engine='openpyxl', mode='a', if_sheet_exists="replace") as writer:  
            df.to_excel(writer, sheetname)
    else:
        with ExcelWriter(f'{filename}.xlsx', engine='openpyxl', mode='wb') as writer:
            df.to_excel(writer, sheetname)


def format_related_vulnerabilities(related_vulns):
    """Formatea las vulnerabilidades relacionadas en una cadena de texto."""
    formatted_vulns = []
    for vuln in related_vulns:
        summary = "; ".join([f"{summary['cvssVersion']}: {summary['cvssAttackVector']}/{summary['cvssAttackComplexity']}/{summary['cvssAvailabilityImpact']}" for summary in vuln.get('cvssSummaries', [])])
        formatted_vulns.append(f"{vuln['id']} (Severidad: {vuln['severity']}, Resumen CVSS: {summary})")
    return ", ".join(formatted_vulns)

def main():
    example = {
        "totalVulnCount": 74,
        "criticalCount": 0,
        "highCount": 3,
        "mediumCount": 25,
        "lowCount": 36,
        "negligibleCount": 10,
        "unknownCount": 0,
        "findings": {
            "High": [
            {
                "name": "libc-bin",
                "type": "deb",
                "version": "2.35-0ubuntu3.1",
                "id": "CVE-2023-4911",
                "source": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2023-4911",
                "severity": "High",
                "fix": "2.35-0ubuntu3.4",
                "locations": [
                "/usr/share/doc/libc-bin/copyright",
                "/var/lib/dpkg/status"
                ],
                "cvssSummaries": [],
                "relatedVulnerabilities": [
                {
                    "id": "CVE-2023-4911",
                    "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-4911",
                    "severity": "High",
                    "cvssSummaries": [
                    {
                        "cvssVersion": "3.1",
                        "cvssAttackVector": "L",
                        "cvssAttackComplexity": "L",
                        "cvssAvailabilityImpact": "H"
                    },
                    {
                        "cvssVersion": "3.1",
                        "cvssAttackVector": "L",
                        "cvssAttackComplexity": "L",
                        "cvssAvailabilityImpact": "H"
                    }
                    ]
                }
                ]
            },
            {
                "name": "libc6",
                "type": "deb",
                "version": "2.35-0ubuntu3.1",
                "id": "CVE-2023-4911",
                "source": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2023-4911",
                "severity": "High",
                "fix": "2.35-0ubuntu3.4",
                "locations": [
                "/usr/share/doc/libc6/copyright",
                "/var/lib/dpkg/status"
                ],
                "cvssSummaries": [],
                "relatedVulnerabilities": [
                {
                    "id": "CVE-2023-4911",
                    "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-4911",
                    "severity": "High",
                    "cvssSummaries": [
                    {
                        "cvssVersion": "3.1",
                        "cvssAttackVector": "L",
                        "cvssAttackComplexity": "L",
                        "cvssAvailabilityImpact": "H"
                    },
                    {
                        "cvssVersion": "3.1",
                        "cvssAttackVector": "L",
                        "cvssAttackComplexity": "L",
                        "cvssAvailabilityImpact": "H"
                    }
                    ]
                }
                ]
            },
            ]
        }
    }


    resumen_vulnerabilidades = {
        "Total Vulnerabilidades": example["totalVulnCount"],
        "Críticas": example["criticalCount"],
        "Altas": example["highCount"],
        "Medias": example["mediumCount"],
        "Bajas": example["lowCount"],
        "Negligibles": example["negligibleCount"],
        "Desconocidas": example["unknownCount"]
    }

    # Convertir el resumen en un DataFrame
    df_resumen = pd.DataFrame([resumen_vulnerabilidades])

    # Preparar detalles de los hallazgos
    detalles_vulnerabilidades = []
    for severity, findings in example["findings"].items():
        for finding in findings:
            finding["relatedVulnerabilities"] = format_related_vulnerabilities(finding.get("relatedVulnerabilities", []))
            finding["severity"] = severity  # Añadir la severidad a cada hallazgo
            detalles_vulnerabilidades.append(finding)

    df_detalles = pd.json_normalize(detalles_vulnerabilidades)

    with pd.ExcelWriter("reporte_vulnerabilidades.xlsx", engine="xlsxwriter") as writer:
        df_resumen.to_excel(writer, sheet_name="Resumen", index=False)
        df_detalles.to_excel(writer, sheet_name="Detalles", index=False)
        workbook  = writer.book
        worksheet_resumen = writer.sheets['Resumen']
        worksheet_detalles = writer.sheets['Detalles']

        # Estilos personalizados
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#95b6fc',
            'border': 1})

        # Aplicar estilos a los encabezados
        for col_num, value in enumerate(df_resumen.columns.values):
            worksheet_resumen.write(0, col_num, value, header_format)
        for col_num, value in enumerate(df_detalles.columns.values):
            worksheet_detalles.write(0, col_num, value, header_format)

        # Ajustar el ancho de las columnas
        worksheet_resumen.set_column('A:H', 20)
        worksheet_detalles.set_column('A:H', 20)

        # Aplicar formato condicional
        format_rojo = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
        format_amarillo = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500'})
        format_verde = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})

        # Suponiendo que las columnas B, C y D contienen las sumatorias de vulnerabilidades
        for col in ['B', 'C', 'D']:
            worksheet_resumen.conditional_format(f'{col}2:{col}1000', {'type': 'cell',
                                                                    'criteria': '>=',
                                                                    'value': 10,
                                                                    'format': format_rojo})
            worksheet_resumen.conditional_format(f'{col}2:{col}1000', {'type': 'cell',
                                                                    'criteria': 'between',
                                                                    'minimum': 5,
                                                                    'maximum': 9,
                                                                    'format': format_amarillo})
            worksheet_resumen.conditional_format(f'{col}2:{col}1000', {'type': 'cell',
                                                                    'criteria': '<',
                                                                    'value': 5,
                                                                    'format': format_verde})

main()