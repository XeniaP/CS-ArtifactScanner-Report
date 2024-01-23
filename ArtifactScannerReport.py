import sys
import pandas as pd
import json


def format_related_vulnerabilities(related_vulns):
    """Formatea las vulnerabilidades relacionadas en una cadena de texto."""
    formatted_vulns = []
    for vuln in related_vulns:
        summary = "; ".join([f"{summary['cvssVersion']}: {summary['cvssAttackVector']}/{summary['cvssAttackComplexity']}/{summary['cvssAvailabilityImpact']}" for summary in vuln.get('cvssSummaries', [])])
        formatted_vulns.append(f"{vuln['id']} (Severidad: {vuln['severity']}, Resumen CVSS: {summary})")
    return ", ".join(formatted_vulns)

# Función para aplanar y extraer los datos de la sección 'vulnerability'
def format_summary_vulnerabilities(vulnerability_data):
    resumen_vulnerabilidades = {
        "Total Vulnerabilidades":  vulnerability_data["totalVulnCount"],
        "Críticas": vulnerability_data["criticalCount"],
        "Altas": vulnerability_data["highCount"],
        "Medias": vulnerability_data["mediumCount"],
        "Bajas": vulnerability_data["lowCount"],
        "Negligibles": vulnerability_data["negligibleCount"],
        "Desconocidas": vulnerability_data["unknownCount"]
    }

    # Convertir el resumen en un DataFrame
    df_resumen = pd.DataFrame([resumen_vulnerabilidades])

    # Preparar detalles de los hallazgos
    detalles_vulnerabilidades = []
    for severity, findings in vulnerability_data["findings"].items():
        for finding in findings:
            finding["relatedVulnerabilities"] = format_related_vulnerabilities(finding.get("relatedVulnerabilities", []))
            finding["severity"] = severity  # Añadir la severidad a cada hallazgo
            detalles_vulnerabilidades.append(finding)

    df_detalles = pd.json_normalize(detalles_vulnerabilidades)

    return df_resumen, df_detalles

def export_file(df_resumen, df_detalles, nombre_imagen):
    with pd.ExcelWriter(f"reporte_vulnerabilidades-{nombre_imagen}.xlsx", engine="xlsxwriter") as writer:
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
        worksheet_detalles.set_column('A:I', 20)
    print(f"Reporte generado: reporte_vulnerabilidades-{nombre_imagen}.xlsx")

def main():
    # Leer desde stdin
    if len(sys.argv) < 2:
        print("Uso: python report.py [nombre_imagen] [archivo_entrada]")
        sys.exit(1)
    nombre_imagen = sys.argv[1]
    json_data = json.load(sys.stdin)
    # Procesar los datos de 'vulnerability'
    df_resumen, df_detalles = format_summary_vulnerabilities(json_data)
    export_file(df_resumen, df_detalles, nombre_imagen)

if __name__ == "__main__":
    main()
