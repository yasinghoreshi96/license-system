#include <QTextStream>
#include <Qca-qt5/QtCrypto/QtCrypto>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QByteArray>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <QMessageBox>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QProcess>
#include <QFile>
#include <QDebug>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <QNetworkInterface>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QCryptographicHash>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QDebug>
#include <QCryptographicHash>
#include <QByteArray>

const QString LICENSE_FILE_PATH = "license_17333.bin";
const QString PUBLIC_KEY_PATH = "/home/yasin/Desktop/my_flask_app/public_key.pem";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    validateOffline();
    manager = new QNetworkAccessManager(this);
    connect(manager, &QNetworkAccessManager::finished, this, &MainWindow::on_validateReply);
}

MainWindow::~MainWindow()
{
    delete ui;
}

RSA* MainWindow::loadPublicKey(const QString &publicKeyPath)
{
    QFile file(publicKeyPath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "error", "Cannot open public key file");
        return nullptr;
    }

    QByteArray keyData = file.readAll();
    file.close();

    BIO *bio = BIO_new_mem_buf(keyData.data(), keyData.size());
    if (!bio) {
        QMessageBox::warning(this, "error", "Failed to create BIO");
        return nullptr;
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa) {
        QMessageBox::warning(this, "Error", "Failed to load public key");
        return nullptr;
    }

    return rsa;
}

QByteArray MainWindow::decryptWithPublicKey(RSA *rsa, const QByteArray &encryptedData)
{
    int rsaSize = RSA_size(rsa);
    QByteArray decryptedMessage(rsaSize, '\0');
    int result = RSA_public_decrypt(
        encryptedData.size(),
        reinterpret_cast<const unsigned char*>(encryptedData.data()),
        reinterpret_cast<unsigned char*>(decryptedMessage.data()),
        rsa,
        RSA_PKCS1_PADDING
    );

    if (result == -1) {
        qDebug() << "failed to decrypt message";
        return QByteArray();
    }

    return decryptedMessage.left(result);
}


//for mac license
QByteArray MainWindow::encryptWithPublicKey(RSA *rsa, const QByteArray &data)
{
    QByteArray encryptedData(RSA_size(rsa), 0);
    int result = RSA_public_encrypt(data.size(),
                                    reinterpret_cast<const unsigned char*>(data.constData()),
                                    reinterpret_cast<unsigned char*>(encryptedData.data()),
                                    rsa, RSA_PKCS1_PADDING);

    if (result == -1) {
        char err[120];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        QMessageBox::warning(this, "error", QString("encryption failed:  ").arg(err));
        return QByteArray();
    }
    ui->statusLabel->setText(encryptedData);


    return encryptedData.left(result);
}

//for mac address
QByteArray MainWindow::encryptWithPublicKey2(const QString &data) {
    QFile file("/home/yasin/Desktop/my_flask_app/public_key.pem");
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "can not open public key file.";
        return QByteArray();
    }
    QByteArray publicKeyPem = file.readAll();
    file.close();

    BIO *bio = BIO_new_mem_buf(publicKeyPem.data(), publicKeyPem.size());
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa) {
        qDebug() << "failed to create rsa.";
        return QByteArray();
    }

    int rsaLen = RSA_size(rsa);
    unsigned char *encryptedData = new unsigned char[rsaLen];
    int result = RSA_public_encrypt(data.size(), reinterpret_cast<const unsigned char*>(data.toUtf8().data()), encryptedData, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (result == -1) {
        qDebug() << "rsa encryption failed: " << ERR_error_string(ERR_get_error(), NULL);
        delete[] encryptedData;
        return QByteArray();
    }

    QByteArray encryptedByteArray(reinterpret_cast<char*>(encryptedData), result);
    delete[] encryptedData;
    return encryptedByteArray;
}



QString MainWindow::getMacAddress() {
    foreach(QNetworkInterface interface, QNetworkInterface::allInterfaces()) {
        if (!(interface.flags() & QNetworkInterface::IsLoopBack)) {
            return interface.hardwareAddress();
        }
    }
    return QString();
}

void MainWindow::on_validateButton_clicked()
{
    RSA *rsa = loadPublicKey(PUBLIC_KEY_PATH);
    if (!rsa) {
        return;
    }

    QFile file(LICENSE_FILE_PATH);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "error", "cannot open license file");
        return;
    }

    QByteArray encryptedLicense = file.readAll();
    file.close();

    QByteArray decryptedHash = decryptWithPublicKey(rsa, encryptedLicense);
    if (decryptedHash.isEmpty()) {
        return;
    }
    QString decryptedHashString = QString::fromUtf8(decryptedHash.data(), decryptedHash.size());
    QMessageBox::information(this, "decryptedHashString", decryptedHashString);
    //my testt for writing to file
    QFile file2("example.txt");
        if (!file2.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qDebug() << "Could not open file for writing";

        }
        QTextStream out(&file2);
        out << decryptedHash.data();
        file2.close();



    QByteArray reEncryptedHash = encryptWithPublicKey(rsa, decryptedHash);
    if (reEncryptedHash.isEmpty()) {
        return;
    }
    QString macAddress = getMacAddress();

    qDebug() << "MAC address obtained:" << macAddress;

    QByteArray encryptedMac = encryptWithPublicKey2(macAddress).toBase64();
    qDebug() << "enc mac address obtained:" << QString(encryptedMac);
    QJsonObject jsonObj;

    jsonObj["encrypted_hash"] = QString(reEncryptedHash.toHex());
    jsonObj["encrypted_mac"] = QString(encryptedMac);
    QNetworkRequest request(QUrl("http://localhost:8000/api/validate_license/"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    manager->post(request, QJsonDocument(jsonObj).toJson());

    RSA_free(rsa);
}











//for rsa decryption
void MainWindow::decryptAndDisplayMac2(const QString &encryptedMacBase64)
{
    QByteArray encryptedMac = QByteArray::fromBase64(encryptedMacBase64.toUtf8());

    QFile pubKeyFile("/home/yasin/Desktop/my_flask_app/public_key.pem");
    if (!pubKeyFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open public key file";
        return;
    }
    QByteArray pubKeyData = pubKeyFile.readAll();
    pubKeyFile.close();

    BIO *bio = BIO_new_mem_buf(pubKeyData.data(), pubKeyData.size());
    RSA *rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsaPublicKey) {
        qDebug() << "Failed to load public key";
        return;
    }

    // Ensure the decrypted buffer is properly sized
    int rsaSize = RSA_size(rsaPublicKey);
    QByteArray decryptedMac(rsaSize, 0);

    int result = RSA_public_decrypt(encryptedMac.size(),
                                    reinterpret_cast<const unsigned char*>(encryptedMac.data()),
                                    reinterpret_cast<unsigned char*>(decryptedMac.data()),
                                    rsaPublicKey, RSA_PKCS1_PADDING);

    RSA_free(rsaPublicKey);

    if (result == -1) {
        qDebug() << "Decryption failed: " << ERR_get_error();
        return;
    }

    decryptedMac.resize(result);

    if (decryptedMac.size() != 6) {
        qDebug() << "Decrypted MAC address size is not 6 bytes";
        return;
    }

    QString macAddress = QString("%1:%2:%3:%4:%5:%6")
                            .arg((unsigned char)decryptedMac[0], 2, 16, QChar('0'))
                            .arg((unsigned char)decryptedMac[1], 2, 16, QChar('0'))
                            .arg((unsigned char)decryptedMac[2], 2, 16, QChar('0'))
                            .arg((unsigned char)decryptedMac[3], 2, 16, QChar('0'))
                            .arg((unsigned char)decryptedMac[4], 2, 16, QChar('0'))
                            .arg((unsigned char)decryptedMac[5], 2, 16, QChar('0'));

    // Display the MAC address
    QMessageBox::information(this, "Decrypted MAC Address", macAddress);
}







//for AES decryption
void MainWindow::decryptAndDisplayMac3(const QString &encryptedMacBase64)
{

    QByteArray encryptedMac = QByteArray::fromBase64(encryptedMacBase64.toUtf8());


    QByteArray salt = encryptedMac.left(16);
    QByteArray iv = encryptedMac.mid(16, 16);
    QByteArray ciphertext = encryptedMac.mid(32);


    QByteArray password = "mysecretpassword";
    const int keyLength = 32;
    const int iterations = 100000;
    QByteArray key(keyLength, 0);
    PKCS5_PBKDF2_HMAC_SHA1(password.constData(), password.length(), reinterpret_cast<const unsigned char*>(salt.constData()), salt.length(), iterations, keyLength, reinterpret_cast<unsigned char*>(key.data()));


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, reinterpret_cast<const unsigned char*>(key.constData()), reinterpret_cast<const unsigned char*>(iv.constData()));


    QByteArray decryptedMac(ciphertext.size(), 0);
    int len;
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedMac.data()), &len, reinterpret_cast<const unsigned char*>(ciphertext.constData()), ciphertext.size());
    int plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decryptedMac.data()) + len, &len);
    plaintext_len += len;
    decryptedMac.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);


    qDebug() << "decrypted MAC  size:" << decryptedMac.size();
    qDebug() << "decrypted MAC  raw data:" << decryptedMac.toHex();


    if (decryptedMac.size() != 17) {
        qDebug() << "dec mac  size is not 17 bytes";
        return;
    }


    QString macAddress = QString::fromUtf8(decryptedMac);


    QMessageBox::information(this, "decrypted MAC Address", macAddress);
}











//for my offline dec
void MainWindow::validateOffline()
{
    QString savedEncryptedMac;
    QFile file("encrypted_mac.txt");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        savedEncryptedMac = in.readAll();
        file.close();
    }

    if (!savedEncryptedMac.isEmpty()) {
        QString currentMac = getMacAddress();
        if (currentMac.isEmpty()) {
            qDebug() << "Failed to get current MAC address.";
            ui->statusLabel->setText("Failed to get current MAC address.");
            return;
        }


        //QString password = ui->licenseLineEdit->text();
        QString password = "mysecretpassword";

        if (password.isEmpty()) {
            QMessageBox::warning(this, "Error", "Password is empty. Please enter the password.");
            return;
        }


        QByteArray encryptedMac = QByteArray::fromBase64(savedEncryptedMac.toUtf8());


        QByteArray key = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256);


        QByteArray decryptedMac;
        for (int i = 0; i < encryptedMac.size(); ++i) {
            decryptedMac.append(encryptedMac[i] ^ key[i]);
        }


        QString macAddress = QString::fromUtf8(decryptedMac);


        if (macAddress == currentMac) {
            ui->statusLabel->setText("License is valid (offline validation).");
        } else {
            ui->statusLabel->setText("License is invalid. Please validate online.");
        }
    } else {
        qDebug() << "No saved encrypted MAC address found.";
        ui->statusLabel->setText("No saved encrypted MAC address found. Please validate online.");
    }
}

























//for my xor decryption
void MainWindow::decryptAndDisplayMac(const QString &encryptedMacBase64)
{
    QByteArray encryptedMac = QByteArray::fromBase64(encryptedMacBase64.toUtf8());
    QString password = "mysecretpassword";
    //QString password = ui->licenseLineEdit->text();

    if (password.isEmpty()) {
            QMessageBox::warning(this, "Error", "Password is empty. Please enter the password.");
            return;
        }


        //QByteArray encryptedMac = QByteArray::fromBase64(encryptedMacBase64.toUtf8());


        QByteArray key = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256);


        QByteArray decryptedMac;
        for (int i = 0; i < encryptedMac.size(); ++i) {
            decryptedMac.append(encryptedMac[i] ^ key[i]);
        }

        //qDebug() << "decrypted MAC  size:" << decryptedMac.size();
        //qDebug() << "decrypted MAC  raw data:" << decryptedMac.toHex();

        if (decryptedMac.size() != 17) { // The MAC address string "DC:F5:05:80:52:45" is 17 bytes long
            qDebug() << "Decrypted MAC address size is not 17 bytes";
            QMessageBox::warning(this, "Error", "Decrypted MAC address size is not 17 bytes.");
            return;
        }


        QFile file("encrypted_mac.txt");
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << encryptedMacBase64;
            file.close();
        } else {
            qDebug() << "Failed to open file for writing.";
            QMessageBox::warning(this, "Error", "Failed to open file for writing.");
            return;
        }


        QString macAddress = QString::fromUtf8(decryptedMac);

        QMessageBox::information(this, "Decrypted MAC Address", macAddress);
        ui->statusLabel->setText("License is valid.");
}





















void MainWindow::on_validateReply(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray response = reply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response);
        QJsonObject jsonObj = jsonDoc.object();
        if (jsonObj["status"] == "valid") {

            ui->statusLabel->setText("License is valid");
            QString encryptedMacBase64 = jsonObj["encrypted_mac"].toString();
            //QString encryptedMacBase64 = jsonObject["encrypted_mac"].toString();
            //decryptAndDisplayMac(encryptedMacBase64);
            decryptAndDisplayMac(encryptedMacBase64);
            QByteArray encryptedMac = QByteArray::fromBase64(encryptedMacBase64.toUtf8());

            RSA *rsa = loadPublicKey(PUBLIC_KEY_PATH);
            if (!rsa) {
                         return;
                      }

            //QByteArray decryptedMac = decryptWithPublicKey(rsa, encryptedMac);
            //QString decryptedMacString = QString::fromUtf8(decryptedMac.data(), decryptedMac.size());
            //qDebug() << "decryptedMacString  :" << decryptedMacString;
            //ui->statusLabel->setText(decryptedMacString);
        } else {
            ui->statusLabel->setText("License is invalid");
        }
    } else {
        ui->statusLabel->setText("Error validating license");
    }
    reply->deleteLater();
}
