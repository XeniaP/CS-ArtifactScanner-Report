import unittest
from unittest.mock import patch, mock_open
from export_report_tmas import ExportExcel
import pandas as pd
import os, sys
from export_report_tmas import process_file
from export_report_tmas import main

import test_script

class TestExportExcel(unittest.TestCase):
    def setUp(self):
        self.patcher_argv = patch('sys.argv')
        self.patcher_os_path = patch('os.path')
        self.patcher_open = patch('builtins.open', mock_open(read_data='{"key": "value"}'))
        self.mock_argv = self.patcher_argv.start()
        self.mock_os_path = self.patcher_os_path.start()
        self.mock_open = self.patcher_open.start()

    def tearDown(self):
        self.patcher_argv.stop()
        self.patcher_os_path.stop()
        self.patcher_open.stop()

    @patch('tu_script.logger')
    @patch('tu_script.proces_data')
    @patch('tu_script.cargar_json_con_validacion', return_value=({}, 'utf-8'))
    def test_main_with_valid_arguments(self, mock_cargar, mock_procesar, mock_logger):
        self.mock_argv.__getitem__.side_effect = lambda x: ['script_name', 'arg1', '--resultFile', 'fake_file.json']
        self.mock_os_path.exists.return_value = True
        
        main()

        mock_cargar.assert_called_once()
        mock_procesar.assert_called_once()
        mock_logger.info.assert_called_with('File loaded Successfully with encode: utf-8')

    @patch('tu_script.logger')
    def test_main_with_insufficient_arguments(self, mock_logger):
        self.mock_argv.__getitem__.side_effect = lambda x: ['script_name', 'arg1']

        with self.assertRaises(SystemExit) as cm:
            main()
        
        self.assertEqual(cm.exception.code, 1)
        mock_logger.error.assert_not_called()  # Asegurándose de que no se registran errores antes de sys.exit


    def test_export_excel_creates_file(self):
        # Preparación
        df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
        filename = 'test_output.xlsx'
        sheetname = 'TestData'

        # Acción
        ExportExcel(df, filename, sheetname)

        # Verificación
        self.assertTrue(os.path.exists(filename))

        # Limpieza
        if os.path.exists(filename):
            os.remove(filename)
    
    def create_test_file(self, content, encoding):
        """Crea un archivo de prueba con el contenido y la codificación especificados."""
        filepath = f'testfile_{encoding}.txt'
        with open(filepath, 'w', encoding=encoding) as f:
            f.write(content)
        return filepath

    def test_file_encoding_handling(self):
        """Prueba cómo el script maneja archivos con diferentes codificaciones."""
        test_strings = "Este es un texto de prueba con caracteres especiales: ñ, á, ü."
        encodings = ['utf-8', 'iso-8859-1', 'utf-16','iso-8859-15','utf-32','windows-1252','ascii']

        for encoding in encodings:
            with self.subTest(encoding=encoding):
                filepath = self.create_test_file(test_strings, encoding)
                try:
                    # Aquí llamas a la función de tu script que procesa el archivo
                    result = process_file(filepath)
                    # Verifica el resultado esperado, por ejemplo, que no haya errores o que el contenido sea correcto
                    self.assertTrue(result, "El archivo no se procesó correctamente")
                finally:
                    # Eliminar el archivo de prueba después de cada subtest
                    if os.path.exists(filepath):
                        os.remove(filepath)

if __name__ == '__main__':
    unittest.main()
