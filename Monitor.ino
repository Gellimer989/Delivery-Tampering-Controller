#include <WiFiEspClient.h>
#include "SoftwareSerial.h"
#include "WiFiEsp.h"
#include <Servo.h>
#include <Crypto.h>
#include <AES.h>
#include <CBC.h>
#include <CRT.h>
#include <Curve25519.h>

#define AES_BLOCK_SIZE 16

SoftwareSerial softserial(4, 5); 
SoftwareSerial MyBlue(3,2);

byte privateKeyMonitor[32] = {
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
        0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x01
      };


CBC<AES128> cbc;
Servo Servo1;

long duration;
int open =1;

String flag;
char ssid[]="Iot";            // your network SSID (name)
char password[]="apov422422";  
int status = WL_IDLE_STATUS; 
WiFiEspClient client;

IPAddress ip(192,168,50,197);

const int TRIGGER_PIN = 7;
const int ECHO_PIN    = 6;

String btCode;

String decCode;

byte received[AES_BLOCK_SIZE];
byte plaintext[] = {0x68};//104
byte output[AES_BLOCK_SIZE];

bool recv= false;
byte sharedSecret[32];


void setup() {
 // privateKeyMonitor[0] &= 0xF8;
 // privateKeyMonitor[31] = (privateKeyMonitor[31] & 0x7F) | 0x40;
  //Curve25519::eval(sharedSecret, privateKeyMonitor, publicKeyServer);
  

  Serial.begin(9600);   // initialize serial for debugging
  softserial.begin(115200);
  softserial.write("AT+CIOBAUD=9600\r\n");
  softserial.write("AT+RST\r\n");
  softserial.begin(9600);    // initialize serial for ESP module
  WiFi.init(&softserial);    // initialize ESP module

  Servo1.attach(9);

  pinMode(TRIGGER_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  // attempt to connect to WiFi network
  while ( status != WL_CONNECTED) {
    Serial.print("Attempting to connect to WPA SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network
    status = WiFi.begin(ssid, password);
  }
  
  Serial.println("Connected to wifi");
  Serial.println("\nStarting connection to server...");
  
  Servo1.write(-50);
  if (client.connect(ip, 1234)) {
    Serial.println("Connected to server");
    client.println("0");

    while(!recv) {
      if(client.available() >= AES_BLOCK_SIZE){   
        
        String decString;     
        client.read(received, AES_BLOCK_SIZE);
        char plat[AES_BLOCK_SIZE];
        decryptMine(&cbc, received, plat);
       
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
          decString.concat(plat[i]);
        }

        for(int i = 0; i < AES_BLOCK_SIZE; i++){
            iv[i] ^= plat[15]&0xFF;
        }

        Serial.println(decString);
        btCode =decString;
        recv = true;
      }
    }
  }  
  
  MyBlue.begin(9600);
}

void loop(){  
  digitalWrite(TRIGGER_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIGGER_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIGGER_PIN, LOW);

  unsigned long duration = pulseIn(ECHO_PIN, HIGH);

  float distance = duration * 0.034 / 2;
  
 // Serial.println(distance);
  
  MyBlue.listen();
  
  if (MyBlue.available())
    flag=MyBlue.readString();
  
  if (flag.equals(btCode)){
    Serial.println("BOX OPENED"); 
    Servo1.write(170);
    open=0;
    delay (1000);
  }else if(flag.equals("0")){
    Serial.println("BOX CLOSED"); 
    Servo1.write(-100);
    open=1;
    delay (1000);
  }
  
  if ((distance > 20 || distance == 0) && open==1 ) {
    Serial.println(distance);
    Serial.println("Motion detected!"); 
    softserial.listen();
    encriptMine(&cbc, plaintext);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
      decCode.concat(output[i]);
      decCode.concat(" ");
    }
    client.println(decCode);
    Serial.println(decCode); 
   }

  delay(1000);
  
}

void decryptMine(Cipher* cbc, byte *ciphertext, byte *plaintext){
  cbc->clear();
  cbc->setKey(secretKey, AES_BLOCK_SIZE);
  cbc->setIV(iv, AES_BLOCK_SIZE);
  cbc->decrypt(plaintext, ciphertext, AES_BLOCK_SIZE);
}


void encriptMine(Cipher* cbc,  byte *plaintext){
  cbc->clear();
  cbc->setKey(secretKey, AES_BLOCK_SIZE);
  cbc->setIV(iv, AES_BLOCK_SIZE);
  cbc->encrypt(output, plaintext, AES_BLOCK_SIZE);
}

