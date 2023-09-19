#include <Crypto.h>
#include <AES.h>
#include <CBC.h>
#include <CRT.h>
#include <Curve25519.h>
#include <WiFiEspClient.h>
#include "SoftwareSerial.h"
#include "WiFiEsp.h"

#define AES_BLOCK_SIZE 16

byte privateKeyController[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
      };

byte publicKeyServer[32] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
      };

byte secretKey[AES_BLOCK_SIZE] = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25
      };

// Vettore di inizializzazione per AES
byte iv[AES_BLOCK_SIZE] = { 
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x01
      };


SoftwareSerial softserial(5,4); 
int pinBuzzer = 10;

CBC<AES128> cbc;
WiFiEspClient client;

IPAddress ip(192,168,50,197);
char ssid[] = "Iot";         // Nome della rete Wi-Fi
char password[] = "apov422422"; // Password della rete Wi-Fi
int serverPort = 80;              // Porta del server
int status = WL_IDLE_STATUS; 

byte sharedSecret[32];
byte received[AES_BLOCK_SIZE];

String decCode;

void setup() {

  // privateKeyController[0] &= 0xF8;
  // privateKeyController[31] = (privateKeyController[31] & 0x7F) | 0x40;
  // Curve25519::eval(sharedSecret, privateKeyController, publicKeyServer);
  
  Serial.begin(9600);   // initialize serial for debugging
  softserial.begin(115200);
  softserial.write("AT+CIOBAUD=9600\r\n");
  softserial.write("AT+RST\r\n");
  softserial.begin(9600);    // initialize serial for ESP module
  WiFi.init(&softserial);

  pinMode(pinBuzzer, OUTPUT);    

  WiFi.begin(ssid, password);
   if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  while ( status != WL_CONNECTED) {
    Serial.print("Attempting to connect to WPA SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network
    status = WiFi.begin(ssid, password);
  }  
  Serial.println("Connected to wifi");
  printWifiStatus();
  Serial.println("\nStarting connection to server...");

 if (client.connect(ip, 1234)) {
    Serial.println("Connected to server");
    client.println("1");
  }
  
}

void loop() {
  
  if (client.available() >= AES_BLOCK_SIZE) {
    client.read(received, AES_BLOCK_SIZE);
    Serial.println("Received: ");

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        Serial.print(received[i]);
        Serial.print(" ");
    }
    byte ciphertext[AES_BLOCK_SIZE];
    char plaintext[AES_BLOCK_SIZE];
    decryptMine(&cbc, received, AES_BLOCK_SIZE, plaintext);
   
    for (int i = 0; i < 6; i++) {
        Serial.print(plaintext[i]); 
        decCode.concat(plaintext[i]);
    }
    if(decCode.equals("123456")){
      tone(pinBuzzer,1000);
    }
  }else{
    if (!client.connected()) {
      Serial.println("Connection lost. Reconnecting...");

    // retring a connection
      if (client.connect(ip, 1234)) {
        Serial.println("Reconnected to server");
        client.println("1");
      } else {
        Serial.println("Reconnection failed");
      }
    }
  }
  delay(1000);
}

void decryptMine(Cipher* cbc, byte *ciphertext, int length, byte *plaintext){
  cbc->clear();
  cbc->setKey(secretKey, AES_BLOCK_SIZE);
  cbc->setIV(iv, AES_BLOCK_SIZE);
  cbc->decrypt(plaintext, ciphertext, AES_BLOCK_SIZE);
}

void printWifiStatus(){
  // print the SSID of the network you're attached to
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your WiFi shield's IP address
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);
}


