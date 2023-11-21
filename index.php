<?php

$pdfFilePath = __DIR__ . '/files/doc1.pdf';
readPdfSignature($pdfFilePath);

function readPdfSignature(string $pdfFilePath): void
{
    $resultCertsFilePath = __DIR__ . '/result_certs.txt';
    if (file_exists($resultCertsFilePath)) {
        unlink($resultCertsFilePath);
    }

    $resultEcpFilePath = __DIR__ . '/result_ecp.txt';
    if (file_exists($resultEcpFilePath)) {
        unlink($resultEcpFilePath);
    }

    $resultFilePath = __DIR__ . '/result.txt';
    if (file_exists($resultFilePath)) {
        unlink($resultFilePath);
    }

    if (file_exists($pdfFilePath)) {
        $pdfFileContent = file_get_contents($pdfFilePath); // Считываем содержимое PDF-файла

        // Ищем определённую последовательность символов
        $matchResult = preg_match(
            '/ByteRange.*Contents<[^>]+>/is',
            $pdfFileContent,
            $matches
        );

        if ($matchResult === 1) {
            $matchResult = preg_match('/(?<=Contents<)[^>]+(?=>)/is', $matches[0], $matches); // Очищаем от ненужного
            if ($matchResult === 1) {
                $tempDirPath = __DIR__ . '/temp';
                if (!file_exists($tempDirPath)) {
                    mkdir($tempDirPath); // Создаём временную папку
                }

                $signatureFilePath = $tempDirPath . '/'
                    . str_replace(['.', ' '], '', microtime()) . '.dat'; // Временный файл

                file_put_contents($signatureFilePath, hex2bin($matches[0]));

                // Расшифровываем данные электронной подписи
                $certs = shell_exec(
                    "openssl pkcs7 -in {$signatureFilePath} -inform DER -print_certs"
                );
                unlink($signatureFilePath); // Удаляем временный файл

                file_put_contents($resultCertsFilePath, print_r($certs, true));

                // Ищем определённые записи в полученном результате >>>
                $subject = '';
                $matchResult = preg_match('/^subject=.+$/im', $certs, $matches);
                if ($matchResult === 1) {
                    $subject = str_replace('subject=', '', $matches[0]);
                    $subject = str_replace('\\', '%', $subject);
                    $subject = urldecode($subject);
                }

                $issuer = '';
                $matchResult = preg_match('/^issuer=.+$/im', $certs, $matches);
                if ($matchResult === 1) {
                    $issuer = str_replace('issuer=', '', $matches[0]);
                    $issuer = str_replace('\\', '%', $issuer);
                    $issuer = urldecode($issuer);
                }

                $certificateData = '';
                $matchResult = preg_match(
                    '/-----BEGIN CERTIFICATE-----.+-----END CERTIFICATE-----/is',
                    $certs,
                    $matches
                );
                if ($matchResult === 1) {
                    $signatureFilePath = $tempDirPath . '/' . str_replace(['.', ' '], '', microtime()) . '.dat';
                    file_put_contents($signatureFilePath, $matches[0]);
                    $certificateData = shell_exec("openssl x509 -in {$signatureFilePath} -text -noout");
                    unlink($signatureFilePath);
                }

                $result = 'SUBJECT';
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= $subject;
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= '===============================';
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= 'ISSUER';
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= $issuer;
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= '===============================';
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= 'CERTIFICATE DATA';
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                $result .= $certificateData;
                $result .= PHP_EOL;
                $result .= PHP_EOL;
                file_put_contents($resultEcpFilePath, print_r($result, true));
                // <<< Ищем определённые записи в полученном результате

                if (!empty($certificateData)) {
                    // Расшифровываем сертификат из электронной подписи и получаем информационные данные >>>
                    // Серийный номер, строка "Serial Number:"
                    $serial = '';
                    $matchResult = preg_match('/^\s*Serial Number:.+$/m', $certificateData, $matches);
                    if ($matchResult !== 1) {
                        $certificateDataPruned = preg_replace('/^.+(?=Serial Number:)/is', '', $certificateData);
                        $certificateDataPrunedStrings = explode("\n", $certificateDataPruned);
                        $serial = str_replace(':', '', $certificateDataPrunedStrings[1]);
                        $serial = trim($serial);
                        $matchResult = preg_match('/^[0-9a-f]$/i', $serial, $matches);
                    }
                    if ($matchResult === 1) {
                        $serial = trim($matches[0]);
                        $serial = str_replace('Serial Number:', '', $serial);
                        $serial = str_replace(':', '', $serial);
                        $serial = trim($serial);
                    }

                    // Полезные данные из строки "Subject:":
                    // CN - Имя директора
                    // O - Название учреждения
                    // title - Должность
                    $subjectCn = '';
                    $subjectO = '';
                    $subjectTitle = '';
                    $matchResult = preg_match('/^\s*Subject:.+$/m', $certificateData, $matches);
                    if ($matchResult !== 1) {
                        $certificateDataPruned = preg_replace('/^.+(?=Subject:)/is', '', $certificateData);
                        $certificateDataPrunedStrings = explode("\n", $certificateDataPruned);
                        $subject = str_replace(':', '', $certificateDataPrunedStrings[1]);
                        $subject = trim($subject);
                        $matchResult = preg_match('/CN =/i', $subject, $matches);
                        if ($matchResult === 1) {
                            $matches[0] = $subject;
                        }
                    }

                    if ($matchResult === 1) {
                        $subject = trim($matches[0]);
                        $subject = str_replace('Subject:', '', $subject);
                        $subject = str_replace('\\', '%', $subject);
                        $subject = urldecode($subject);

                        // CN - Имя директора
                        $matchResult = preg_match('/CN = [^,]+,/is', $subject, $matches);
                        if ($matchResult !== 1) {
                            $matchResult = preg_match('/CN = [^,]+$/is', $subject, $matches);
                        }
                        if ($matchResult === 1) {
                            $subjectCn = str_replace(['CN =', ',', '%'], '', $matches[0]);
                            $subjectCn = trim($subjectCn);
                        }

                        // O - Название учреждения
                        $matchResult = preg_match('/O = [^,]+,/is', $subject, $matches);
                        if ($matchResult !== 1) {
                            $matchResult = preg_match('/O = [^,]+$/is', $subject, $matches);
                        }
                        if ($matchResult === 1) {
                            $subjectO = str_replace(['O =', ',', '%'], '', $matches[0]);
                            $subjectO = trim($subjectO);
                        }

                        // title - Должность
                        $matchResult = preg_match('/title = [^,]+,/is', $subject, $matches);
                        if ($matchResult !== 1) {
                            $matchResult = preg_match('/title = [^,]+$/is', $subject, $matches);
                        }
                        if ($matchResult === 1) {
                            $subjectTitle = str_replace(['title =', ',', '%'], '', $matches[0]);
                            $subjectTitle = trim($subjectTitle);
                        }
                    }

                    $result = '';
                    if (!empty($serial)) {
                        $result .= "Serial number: {$serial}";
                        $result .= PHP_EOL;
                    }
                    if (!empty($subjectTitle)) {
                        $result .= $subjectTitle;
                        $result .= ' ';
                    }
                    if (!empty($subjectO)) {
                        $result .= $subjectO;
                        $result .= ' ';
                    }
                    if (!empty($subjectCn)) {
                        $result .= $subjectCn;
                    }
                    $result = trim($result);
                    file_put_contents($resultFilePath, print_r($result, true));
                    // <<< Расшифровываем сертификат из электронной подписи и получаем информационные данные
                } else {
                    file_put_contents($resultFilePath, print_r('Signification not found', true));
                }
            } else {
                file_put_contents($resultFilePath, print_r('Signification not found', true));
            }
        } else {
            file_put_contents($resultFilePath, print_r('Signification not found', true));
        }
    } else {
        file_put_contents($resultFilePath, print_r('File not found', true));
    }
}
