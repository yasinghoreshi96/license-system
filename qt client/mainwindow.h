#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <Qca-qt5/QtCrypto/QtCrypto>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_validateButton_clicked();
    void on_validateReply(QNetworkReply* reply);
    void decryptAndDisplayMac(const QString &encryptedMacBase64);
    void decryptAndDisplayMac2(const QString &encryptedMacBase64);
     void decryptAndDisplayMac3(const QString &encryptedMacBase64);
      void validateOffline();

private:
    Ui::MainWindow *ui;
    QNetworkAccessManager *manager;

    RSA* loadPublicKey(const QString &publicKeyPath);
    QByteArray decryptWithPublicKey(RSA *rsa, const QByteArray &encryptedData);
    QByteArray encryptWithPublicKey(RSA *rsa, const QByteArray &data);
    QByteArray encryptWithPublicKey2(const QString &data);
    QString getMacAddress();

};

#endif // MAINWINDOW_H
