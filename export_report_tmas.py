import sys
import pandas as pd
from pandas import ExcelWriter
import json
import tarfile
import os
import pandas.io.formats.excel
import datetime
import subprocess
import logging
import chardet

logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

pandas.io.formats.excel.ExcelFormatter.header_style = None

contar_nofix = 0

def ExportExcel(df, filename, sheetname):
    try:
        if(os.path.exists(f'{filename}.xlsx')):
            with ExcelWriter(f'{filename}.xlsx', engine='openpyxl', mode='a', if_sheet_exists="replace") as writer:  
                df.to_excel(writer, sheetname)
        else:
            with ExcelWriter(f'{filename}.xlsx', engine='openpyxl', mode='wb') as writer:
                df.to_excel(writer, sheetname)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

import json

def cargar_json_con_validacion(file_path):
    if not os.path.getsize(file_path) > 0:
        raise ValueError("The file is Empty")
    #Solution 2
    with open(file_path, 'rb') as file:
        result = chardet.detect(file.read())
        codification = result['encoding']
        print(f"File encode: {codification}")

        with open(file_path, 'r', encoding=codification) as file:
            return json.load(file), codification


def main(): 
    if len(sys.argv) < 4:
        sys.exit(1)
    now = datetime.datetime.now()
    timestamp = now.strftime('%Y_%m_%d')

    try:
        file_path = os.path.abspath(sys.argv[3])
        if not os.path.exists(file_path):
            print(f"File not Found: {file_path}")
        if(sys.argv[2] == "--resultFile"):
            try:
                data, codificacion_usada = cargar_json_con_validacion(file_path)
                logger.info(f"File loaded Successfully with encode: {codificacion_usada}")
                proces_data(data, sys.argv[1], timestamp)
            except ValueError as e:
                logger.error(f"An unexpected error occurred: {e}")
    except FileNotFoundError:
        logger.error(f"The file at {file_path} was not found.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            logger.error(f"Error executing command: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        logger.error(f"Exception during command execution: {e}")
        return None


def proces_data(data, image_name, timestamp):
    malware_sumary= ""
    if isMalwareScan(data) == True:
        value = data["vulnerability"]
        malware_sumary = {
            'Total Malware Found': data["malware"]["scanResult"],
        }
    else:
        value = data

    vulnerability_sumary = {
        "Total Vulnerabilities": value["totalVulnCount"],
        "Critial": value["criticalCount"],
        "High": value["highCount"],
        "Medium": value["mediumCount"],
        "Low": value["lowCount"],
        "Negligible": value["negligibleCount"],
        "Unknown": value["unknownCount"]
    }
    print(value["totalVulnCount"])

    try:
        with pd.ExcelWriter(f"TM_Artifact_Scanner_Report_{image_name}_{timestamp}.xlsx", engine="xlsxwriter") as writer:
            dfs = []
            workbook  = writer.book
            pd.DataFrame([vulnerability_sumary]).to_excel(writer, sheet_name="Summary", startrow=2, startcol=1, index=False)
            if isMalwareScan(data) == True:
                pd.DataFrame([malware_sumary]).to_excel(writer, sheet_name="Summary", startrow=13, startcol=1, index=False)
                if(data["malware"]["scanResult"] > 0):
                    df_malware_details = pd.json_normalize(extract_malware_details(data['malware']['findings']))
                    df_malware_details.to_excel(writer, sheet_name="Malware Details", index=False)
                    addStyle(workbook, writer.sheets['Malware Details'])
            df = vulnerabilities_details(value, writer, workbook)
            df['CVE ID'] = df['CVE ID'].astype(str)
            df['Year'] = df['CVE ID'].str.extract(r'(20\d{2})')
            year_counts = df['Year'].value_counts()
            df_severity = df
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']
            df_severity['Severity'] = pd.Categorical(df_severity['Severity'], categories=severity_order, ordered=True)
            df_severity_sorted = df_severity.sort_values('Severity')
            pd.DataFrame([{"Total": value['totalVulnCount'],"Fixeable": get_count_fix(), "No Fixeable": value['totalVulnCount']-contar_nofix }]).to_excel(writer, sheet_name="Summary", startrow=7, startcol=1, index=False)
            df_severity_sorted['CVSS Attack Vector'].value_counts().to_excel(writer, sheet_name="Summary", startrow=3, startcol=11, index=True)
            df_severity_sorted['CVSS Attack Complexity'].value_counts().to_excel(writer, sheet_name="Summary", startrow=3, startcol=13, index=True)
            df_severity_sorted['CVSS Availability Impact'].value_counts().to_excel(writer, sheet_name="Summary", startrow=3, startcol=15, index=True)
            year_counts.to_excel(writer, sheet_name='Counts')
            worksheet_resumen = writer.sheets['Summary']
            worksheet_statistics = writer.sheets['Counts']
            
            df.to_excel(writer, sheet_name="Details", index=False)
            
            addGraph(workbook, worksheet_resumen, 'Summary',year_counts)
            addStyle(workbook, worksheet_resumen)
            worksheet_statistics.hide()
        
        logging.info(f"Report generated successfully: TM_Artifact_Scanner_Report_{image_name}_{timestamp}.xlsx")
    except PermissionError:
        logger.error("Error: You do not have permission to write the file.")
    except FileNotFoundError:
        logger.error("Error: The specified directory was not found.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

def sum_count_fix(value):
    global contar_nofix
    contar_nofix += value

def get_count_fix():
    return contar_nofix

def vulnerabilities_details(json, writer, workbook):
    dfs = []
    for key, value in json['findings'].items():
        vulnerability_details = formatDetails(json['findings'][key])
        dataframe = pd.json_normalize(vulnerability_details)
        dfs.append(dataframe)
        dataframe.to_excel(writer, sheet_name="vulns_"+key, index=False)
        addStyle(workbook, writer.sheets["vulns_"+key])
    
    df_final = pd.concat(dfs, ignore_index=True)
    return df_final    
        
def addStyle(workbook, worksheet):
    header_format = workbook.add_format({'bold': True,'text_wrap': True,'valign': 'center','bg_color': '#95b6fc', 'fg_color': '#000000','border': 1})
    value_format = workbook.add_format({'bold': True,'text_wrap': True,'valign': 'center','bg_color': '#FABF8F'})
    nonvalue_format = workbook.add_format({'bold': True,'text_wrap': True,'valign': 'center','bg_color': '#CDCDCD'})
    if (worksheet.name == 'Summary'):
        worksheet.conditional_format('B3:H3', {'type': 'no_blanks','format': header_format, 'multi_range': 'B3:H3 B8:H8 B14:H14'})
        worksheet.conditional_format('B4:H4', {'type': 'cell','criteria': 'greater than','value': 0,'format': value_format, 'multi_range': 'B4:H4 B9:D9 B15'})
        worksheet.conditional_format('B4:H4', {'type': 'cell','criteria': 'greater than','value': 0,'format': nonvalue_format, 'multi_range': 'B4:H4 B9:D9 B15'})
    elif(worksheet.name == 'Malware Details'):
        worksheet.conditional_format('A1:O1', {'type': 'no_blanks','format': header_format})
        header_format.set_align('vcenter')
        worksheet.set_column('A:A', 75)
        worksheet.set_column('D:D', 75)
    else:
        worksheet.conditional_format('A1:O1', {'type': 'no_blanks','format': header_format})
    worksheet.set_column('A:B', 20)
    worksheet.set_column('C:H', 10)

def create_doughnut_chart(title, categories_range, values_range, point_colors, workbook):
    chart = workbook.add_chart({'type': 'doughnut'})
    chart.add_series({
        'name': title,
        'categories': categories_range,
        'values': values_range,
        'points': [{'fill': {'color': color}} for color in point_colors],
        'data_labels': {'percentage': True}
    })
    chart.set_title({'name': title})
    chart.set_style(10)
    return chart

def create_bar_chart(title, categories_range, values_range, workbook, df):
    # Crea una instancia de la clase Chart
    chart = workbook.add_chart({'type': 'column'})
    # Configura la serie de datos para la gráfica, ajusta las celdas según tus datos
    chart.add_series({
        'name':       'Recuento de CVE por Año',
        'categories': '=Counts!$A$2:$A${}'.format(len(df) + 1),
        'values':     '=Counts!$B$2:$B${}'.format(len(df) + 1),
    })
    # Añade un título y nombra los ejes
    chart.set_title({'name': 'Recuento de CVEs por Año'})
    chart.set_x_axis({'name': 'Año'})
    chart.set_y_axis({'name': 'Cantidad de CVEs'})
    # Inserta la gráfica en la hoja de cálculo
    chart.set_title({'name': title})
    chart.set_style(10)
    chart.set_legend({'position': 'bottom'})
    return chart
    

def addGraph(workbook, worksheet, sheet_name, year_counts):
    colors = ['#D32F2F', '#E57373', '#EF9A9A', '#FFCDD2', '#FFE0E0', '#E0E0E0']
    fix_colors = ["#4ecf1f", "#D32F2F"]
    vulnerability_details_chart = create_doughnut_chart('Vulnerability Severities',f'={sheet_name}!$C$3:$H$3',f'={sheet_name}!$C$4:$H$4',colors,workbook)
    vulnerability_fix_chart = create_doughnut_chart('Fix Distribution',f'={sheet_name}!$C$8:$D$8',f'={sheet_name}!$C$9:$D$9',fix_colors,workbook)
    cve_year_chart = create_bar_chart('CVEs by Year',f'={sheet_name}!$C$14:$H$14',year_counts,workbook, year_counts)
    worksheet.insert_chart('B18', vulnerability_details_chart)
    worksheet.insert_chart('H18', vulnerability_fix_chart)
    worksheet.insert_chart('P18', cve_year_chart)

def isMalwareScan(json):
    if "vulnerability" in json and "malware" in json:
        return True
    return False

def formatDetails(json):
    details = []
    for findings in json:
        
        if any(term in findings["fix"] for term in ["not-fixed", "unknown", "wont-fix"]):
            sum_count_fix(1)

        detail = {
            "Name": findings["name"],
            "Type": findings["type"],
            "Version": findings["version"],
            "Severity": findings["severity"],
            "Fix": findings["fix"],
            "Source": findings["source"],
            "Locations": "; ".join(findings["locations"]),
            "Vulnerability ID": findings["id"]
        }
        if len(findings["cvssSummaries"]) == 0 and len(findings["relatedVulnerabilities"]) > 0:
            for related in findings["relatedVulnerabilities"]:
                if(findings['id'] == related['id']):
                    detail["CVE ID"] = findings["id"]
                    cvss_details = extract_cvss_details(related)
                    detail.update(cvss_details)
        elif "CVE" not in findings["id"] and len(findings["relatedVulnerabilities"]) > 0:
            for related in findings["relatedVulnerabilities"]:
                detail["CVE ID"] = related["id"]
                cvss_details = extract_cvss_details(related)
                detail.update(cvss_details)
        elif len(findings["cvssSummaries"]) > 0:
            for related in findings["cvssSummaries"]:
                detail["CVE ID"] = findings["id"]
                cvss_details = extract_cvss_details(findings)
                detail.update(cvss_details)
        
        detail["Total Related Vulnerabilities"] = len(findings["relatedVulnerabilities"])
        details.append(detail)
    return details

def extract_malware_details(malwares):
    malware_details = []
    for malware in malwares:
        for malware_det in malware["foundMalwares"]:
            info = {
                "Layer Digest": malware["layerDigest"],
                "File Name": malware["fileName"],
                "File Size": malware["fileSize"],
                "File SHA256": malware["fileSHA256"],
                "Malware Name": malware_det["malwareName"]
            }
            malware_details.append(info)
    return malware_details

def extract_cvss_details(related_vulnerability):
    cvss_details = {}
    for version in related_vulnerability['cvssSummaries']:
        if version['cvssVersion'] >= '3':
            cvss_details = {
                "CVSS Version": version["cvssVersion"],
                "CVSS Attack Vector": version["cvssAttackVector"],
                "CVSS Attack Complexity": version["cvssAttackComplexity"],
                "CVSS Availability Impact": version["cvssAvailabilityImpact"]
            }
            break
    return cvss_details

if __name__ == '__main__':
    main()