#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gmpxx.h>
#include <unordered_map>
#include <ctime>
#include <cstring>

// ANSI 转义码定义颜色
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

#define AES_KEY_LENGTH 16 // AES 128位密钥长度
#define AES_IV_LENGTH 16  // AES IV长度


// 函数和类的前向声明
bool generateRandomBytes(unsigned char* buffer, int length);        // 生成用于加密操作的随机字节
void mpzToBytes(const mpz_class& number, unsigned char* buffer, size_t bufferSize);                 // 将 mpz_class 转换为字节数组
void bytesToMpz(const unsigned char* buffer, mpz_class& number, size_t bufferSize);                 // 将字节数组转换为 mpz_class
void charToBlock(const char* input, unsigned char* output);         // 将 char* 转换为 16 字节的 unsigned char 数组
void blockToChar(const unsigned char* input, char* output);         // 将 16 字节的 unsigned char 数组转换为 char*
void concatenateBlocks(unsigned char* result, std::initializer_list<const unsigned char*> blocks);  // 拼接多个块
mpz_class calculateF(const mpz_class& x);                           // 计算函数 f(x) 的值，用于加密计算
void printHex(const unsigned char* data, size_t length);            // 以十六进制格式打印数据
void aesEncrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, unsigned char* output, int& outLength, int inputLength); // 使用 AES 128位 CBC 模式加密（使用PKCS#7填充）
void aesDecrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, unsigned char* output, int& outLength, int inputLength); // 使用 AES 128位 CBC 模式解密（使用PKCS#7填充）
void needhamSchroederProtocol();                                    // 模拟 Needham-Schroeder 协议

class KDC;

class User {
public:
    const char* userId; // 用户的 ID
    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_IV_LENGTH];
    unsigned char sessionKey[AES_KEY_LENGTH];
    unsigned char sessionIv[AES_IV_LENGTH];
    mpz_class randomNum;

    User(const char* id);               // 初始化用户的构造函数
    void generateRandomNumber(mpz_class& randomNumber);         // 生成随机数
    void requestTicket(KDC& KDC, const char* targetId, unsigned char* encryptedResult); // 向 KDC 请求会话票据
    void withdrawTicket(unsigned char* encryptedResult, unsigned char* ticket);         // 从加密结果中提取会话票据
    void extractSessionKey(unsigned char* ticket);              // 从票据中提取会话密钥
    void sendEncryptedRandom(unsigned char* encryptedRandom);   // 向另一用户发送加密的随机数
    void sendEncryptedRandomWithFunction(unsigned char* encryptedRandom, unsigned char* encryptedRandomWithF);  // 发送经过函数处理后的加密随机数
    void authenticateUser(unsigned char* encryptedRandomWithF); // 验证另一用户的身份
};

class KDC {
private:
    std::unordered_map<std::string, unsigned char*> keyTable;   // 存储用户密钥的哈希表
    std::unordered_map<std::string, unsigned char*> ivTable;    // 存储用户 IV 的哈希表

    unsigned char* deepCopy(const unsigned char* src, size_t length);   // 深拷贝字节数组

public:
    unsigned char sessionKey[AES_KEY_LENGTH];
    unsigned char sessionIv[AES_IV_LENGTH];

    KDC(std::initializer_list<User> users);         // 使用用户密钥和 IV 初始化 KDC 的构造函数
    ~KDC();     // 释放已分配内存的析构函数
    void generateTicket(const char* requesterId, const char* targetId, const mpz_class& nonce, unsigned char* encryptedResult); // 生成加密的会话票据
};


int main() {
    needhamSchroederProtocol();

    return 0;
}

// 模拟 Needham-Schroeder 协议
void needhamSchroederProtocol() {
    User alice("Alice");
    User bob("Bob");

    KDC KDC({alice, bob});

    unsigned char encryptedResult[7 * AES_KEY_LENGTH];
    alice.requestTicket(KDC, bob.userId, encryptedResult);

    std::memcpy(alice.sessionIv, KDC.sessionIv, AES_IV_LENGTH);
    std::memcpy(bob.sessionIv, KDC.sessionIv, AES_IV_LENGTH);

    unsigned char ticket[3 * AES_KEY_LENGTH];
    alice.withdrawTicket(encryptedResult, ticket);

    bob.extractSessionKey(ticket);

    unsigned char encryptedRandom[2 * AES_KEY_LENGTH];
    bob.sendEncryptedRandom(encryptedRandom);

    unsigned char encryptedRandomWithF[2 * AES_KEY_LENGTH];
    alice.sendEncryptedRandomWithFunction(encryptedRandom, encryptedRandomWithF);

    bob.authenticateUser(encryptedRandomWithF);
}

// 生成用于加密操作的随机字节
bool generateRandomBytes(unsigned char* buffer, int length) {
    if (!RAND_bytes(buffer, length)) {
        std::cerr << RED << "错误: 生成随机字节失败!" << RESET << std::endl;
        return false;
    }
    return true;
}

// 将 mpz_class 转换为字节数组
void mpzToBytes(const mpz_class& number, unsigned char* buffer, size_t bufferSize) {
    std::memset(buffer, 0, bufferSize);                 // 清空缓冲区
    size_t count;
    mpz_export(buffer, &count, 1, sizeof(buffer[0]), 0, 0, number.get_mpz_t());
    if (count < bufferSize) {
        size_t padding = bufferSize - count;
        std::memmove(buffer + padding, buffer, count);  // 将数据向右移动
        std::memset(buffer, 0, padding);                // 左侧填充0
    }
}

// 将字节数组转换为 mpz_class
void bytesToMpz(const unsigned char* buffer, mpz_class& number, size_t bufferSize) {
    number = 0;     // 清空 mpz_class 对象的内容
    mpz_import(number.get_mpz_t(), bufferSize, 1, sizeof(buffer[0]), 0, 0, buffer);
}

// 将 char* 转换为 16 字节的 unsigned char 数组
void charToBlock(const char* input, unsigned char* output) {
    int inputLength = std::strlen(input);
    std::memcpy(output, input, inputLength);
    if (inputLength < AES_KEY_LENGTH)
        std::memset(output + inputLength, ' ', AES_KEY_LENGTH - inputLength);   // 如果输入字符串不足16字节，使用空格填充剩余部分
}

// 将 16 字节的 unsigned char 数组转换为 char*
void blockToChar(const unsigned char* input, char* output) {
    std::memcpy(output, input, AES_KEY_LENGTH);
    int lastIndex = AES_KEY_LENGTH - 1;
    while (lastIndex >= 0 && output[lastIndex] == ' ')      // 从末尾开始查找非填充字符
        --lastIndex;
    output[lastIndex + 1] = '\0';                           // 设置字符串的终止符 '\0'
}

// 拼接多个块
void concatenateBlocks(unsigned char* result, std::initializer_list<const unsigned char*> blocks) {
    int offset = 0;
    for (auto block : blocks) {
        std::memcpy(result + offset, block, AES_KEY_LENGTH);
        offset += AES_KEY_LENGTH;
    }
}

// 计算函数 f(x) 的值，用于加密计算
mpz_class calculateF(const mpz_class& x) {
    return x + 1;
}

// 以十六进制格式打印数据
void printHex(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    std::cout << std::endl;
}

// 使用 AES 128位 CBC 模式加密（使用PKCS#7填充）
void aesEncrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, unsigned char* output, int& outLength, int inputLength) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);   // 初始化加密操作，指定算法为AES-128-CBC，提供密钥和IV
    int len;
    EVP_EncryptUpdate(ctx, output, &len, input, inputLength);       // 执行加密的主要步骤（加密输入的明文块），并将结果存储到输出缓冲区
    outLength = len;
    EVP_EncryptFinal_ex(ctx, output + len, &len);                   // 处理最终的加密块，OpenSSL 自动添加PKCS#7填充
    outLength += len;
    EVP_CIPHER_CTX_free(ctx);
}

// 使用 AES 128位 CBC 模式解密（使用PKCS#7填充）
void aesDecrypt(const unsigned char* input, const unsigned char* key, const unsigned char* iv, unsigned char* output, int& outLength, int inputLength) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);   // 初始化解密操作，指定算法为AES-128-CBC，提供密钥和IV
    int len;
    EVP_DecryptUpdate(ctx, output, &len, input, inputLength);       // 执行解密的主要步骤（解密输入的密文块），并将结果存储到输出缓冲区
    outLength = len;
    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, output + len, &finalLen) <= 0) {   // 处理最终的解密块，OpenSSL 自动处理PKCS#7填充的移除
        std::cerr << RED << "错误: 解密失败!" << RESET << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    outLength += finalLen;
    EVP_CIPHER_CTX_free(ctx);
}

// 初始化用户的构造函数
User::User(const char* id) : userId(id) {
    if (!generateRandomBytes(key, AES_KEY_LENGTH) || !generateRandomBytes(iv, AES_IV_LENGTH)) {
        std::cerr << RED << "错误: 密钥生成失败!" << RESET << std::endl;
        exit(1);
    }
}

// 生成随机数
void User::generateRandomNumber(mpz_class& randomNumber) {
    static gmp_randclass randGen(gmp_randinit_default);     // 在函数内部使用静态变量保存随机数生成器，确保生成器在多次调用中保持状态
    static bool seedInitialized = false;                    // 只在第一次调用时设置种子
    if (!seedInitialized) {
        randGen.seed(time(nullptr));
        seedInitialized = true;
    }
    randomNumber = randGen.get_z_bits(128);                  // 生成128位随机数
}

// 向 KDC 请求会话票据
void User::requestTicket(KDC& KDC, const char* targetId, unsigned char* encryptedResult) {
    generateRandomNumber(randomNum);
    std::cout << BLUE << userId << " 向 KDC 请求访问 " << targetId << " 的票据，并生成随机数 N1:\t" << RESET << std::hex << std::setw(2) << std::setfill('0') << randomNum << std::endl;
    KDC.generateTicket(userId, targetId, randomNum, encryptedResult);
}

// 从加密结果中提取会话票据
void User::withdrawTicket(unsigned char* encryptedResult, unsigned char* ticket) {
    int encryptedLength = 7 * AES_KEY_LENGTH;
    int decryptedLength;
    unsigned char decryptedOutput[6 * AES_KEY_LENGTH];
    aesDecrypt(encryptedResult, key, iv, decryptedOutput, decryptedLength, encryptedLength);
    std::memcpy(sessionKey, decryptedOutput, AES_KEY_LENGTH);
    std::memcpy(ticket, decryptedOutput + 3 * AES_KEY_LENGTH, 3 * AES_KEY_LENGTH);

    std::cout << BLUE << userId << " 解密得到的票据:\t" << RESET;
    printHex(ticket, 3 * AES_KEY_LENGTH);
    std::cout << BLUE << userId << " 得到会话密钥:\t" << RESET;
    printHex(sessionKey, AES_KEY_LENGTH);
}

// 从票据中提取会话密钥
void User::extractSessionKey(unsigned char* ticket) {
    int encryptedLength = 3 * AES_KEY_LENGTH;
    int decryptedLength;
    unsigned char decryptedOutput[2 * AES_KEY_LENGTH];
    aesDecrypt(ticket, key, iv, decryptedOutput, decryptedLength, encryptedLength);
    std::memcpy(sessionKey, decryptedOutput, AES_KEY_LENGTH);

    unsigned char requesterId[AES_KEY_LENGTH];
    std::memcpy(requesterId, decryptedOutput + AES_KEY_LENGTH, AES_KEY_LENGTH);
    char requesterChar[AES_KEY_LENGTH + 1];         // +1 用于存储 '\0' 终止符
    blockToChar(requesterId, requesterChar);
    std::cout << BLUE << requesterChar << " 向 " << userId << " 发送票据, " << RESET;
    std::cout << BLUE << userId << " 得到会话密钥:\t" << RESET;
    printHex(sessionKey, AES_KEY_LENGTH);
}

// 向另一用户发送加密的随机数
void User::sendEncryptedRandom(unsigned char* encryptedRandom) {
    generateRandomNumber(randomNum);
    std::cout << BLUE << userId << "生成随机数 N2:\t" << RESET << randomNum << std::endl;

    unsigned char randomNumBytes[AES_KEY_LENGTH];
    mpzToBytes(randomNum, randomNumBytes, AES_KEY_LENGTH);
    int inputLength = AES_KEY_LENGTH;
    int encryptedLength;
    aesEncrypt(randomNumBytes, sessionKey, sessionIv, encryptedRandom, encryptedLength, inputLength);
}

// 发送经过函数处理后的加密随机数
void User::sendEncryptedRandomWithFunction(unsigned char* encryptedRandom, unsigned char* encryptedRandomWithF) {
    int encryptedLength = 2 * AES_KEY_LENGTH;
    int decryptedLength;
    unsigned char decryptedOutput[AES_KEY_LENGTH];
    aesDecrypt(encryptedRandom, sessionKey, sessionIv, decryptedOutput, decryptedLength, encryptedLength);

    mpz_class randomNumDecrypted;
    bytesToMpz(decryptedOutput, randomNumDecrypted, AES_KEY_LENGTH);
    std::cout << BLUE << userId << " 解密得到的随机数:\t" << RESET << randomNumDecrypted << std::endl;

    mpz_class randomNumModified = calculateF(randomNumDecrypted);
    std::cout << BLUE << userId << " 对随机数作用f函数:\t" << RESET << randomNumModified << std::endl;
    unsigned char randomNumModifiedBytes[AES_KEY_LENGTH];
    mpzToBytes(randomNumModified, randomNumModifiedBytes, AES_KEY_LENGTH);
    int inputLength = AES_KEY_LENGTH;
    aesEncrypt(randomNumModifiedBytes, sessionKey, sessionIv, encryptedRandomWithF, encryptedLength, inputLength);
}

// 验证另一用户的身份
void User::authenticateUser(unsigned char* encryptedRandomWithF) {
    mpz_class randomNumModified = calculateF(randomNum);
    unsigned char randomNumModifiedBytes[AES_KEY_LENGTH];
    mpzToBytes(randomNumModified, randomNumModifiedBytes, AES_KEY_LENGTH);

    int inputLength = AES_KEY_LENGTH;
    int encryptedLength;
    unsigned char encryptedOutput[2 * AES_KEY_LENGTH];
    aesEncrypt(randomNumModifiedBytes, sessionKey, sessionIv, encryptedOutput, encryptedLength, inputLength);
    if (std::memcmp(encryptedRandomWithF, encryptedOutput, 2 * AES_KEY_LENGTH) == 0)
        std::cout << BLUE << userId << " 成功验证了另一用户的身份√" << RESET << std::endl;
    else
        std::cout << RED << "身份验证失败×" << RESET << std::endl;
}

// 使用用户密钥和 IV 初始化 KDC 的构造函数
KDC::KDC(std::initializer_list<User> users) {
    for (const User& user : users) {
        keyTable[user.userId] = deepCopy(user.key, AES_KEY_LENGTH);
        ivTable[user.userId] = deepCopy(user.iv, AES_IV_LENGTH);
    }
}

// 释放已分配内存的析构函数
KDC::~KDC() {
    for (auto& pair : keyTable) {
        delete[] pair.second;
    }
    for (auto& pair : ivTable) {
        delete[] pair.second;
    }
}

// 深拷贝字节数组
unsigned char* KDC::deepCopy(const unsigned char* src, size_t length) {
    unsigned char* dst = new unsigned char[length];
    std::memcpy(dst, src, length);
    return dst;
}

// 生成加密的会话票据
void KDC::generateTicket(const char* requesterId, const char* targetId, const mpz_class& nonce, unsigned char* encryptedResult) {
    if (!generateRandomBytes(sessionKey, AES_KEY_LENGTH) || !generateRandomBytes(sessionIv, AES_IV_LENGTH)) {
        std::cerr << RED << "错误: KDC 密钥生成失败!" << RESET << std::endl;
        exit(1);
    }
    unsigned char ticket[3 * AES_KEY_LENGTH];
    unsigned char input1[2 * AES_KEY_LENGTH];
    unsigned char requesterIdBytes[AES_KEY_LENGTH];
    charToBlock(requesterId, requesterIdBytes);
    concatenateBlocks(input1, {sessionKey, requesterIdBytes});

    int inputLength1 = 2 * AES_KEY_LENGTH;
    int encryptedLength1;
    aesEncrypt(input1, keyTable[targetId], ivTable[targetId], ticket, encryptedLength1, inputLength1);
    std::cout << BLUE << "KDC 生成并加密的票据:\t" << RESET;
    printHex(ticket, encryptedLength1);

    unsigned char nonceBytes[AES_KEY_LENGTH];
    mpzToBytes(nonce, nonceBytes, AES_KEY_LENGTH);
    unsigned char input2[6 * AES_KEY_LENGTH];
    unsigned char targetIdBytes[AES_KEY_LENGTH];
    charToBlock(targetId, targetIdBytes);
    concatenateBlocks(input2, {sessionKey, targetIdBytes, nonceBytes, ticket, ticket + AES_KEY_LENGTH, ticket + 2 * AES_KEY_LENGTH});

    int inputLength2 = 6 * AES_KEY_LENGTH;
    int encryptedLength2;
    aesEncrypt(input2, keyTable[requesterId], ivTable[requesterId], encryptedResult, encryptedLength2, inputLength2);
    std::cout << BLUE << "KDC 生成的加密结果:\t" << RESET;
    printHex(encryptedResult, encryptedLength2);
}
