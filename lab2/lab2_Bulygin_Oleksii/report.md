# Лабораторна робота №2 — Варіант C

## Огляд бібліотеки Crypto++ під macOS

**Тема:** Генерація псевдовипадкових чисел та ключів у бібліотеці Crypto++

---

### Мета роботи

Дослідити механізми генерації криптографічно стійких псевдовипадкових чисел (CSPRNG) та ключів у бібліотеці Crypto++ під операційною системою macOS.

### Бібліотека Crypto++

**Crypto++** (також CryptoPP, libcryptopp) — бібліотека криптографічних алгоритмів з відкритим кодом для C++.

- **Версія:** 8.9.0 (актуальна на момент виконання)
- **Ліцензія:** Boost Software License 1.0
- **Платформи:** Windows, Linux, macOS, Android, iOS
- **Стандарти:** FIPS 140-2, NIST SP 800-90A

### Основні типи даних

Crypto++ визначає власні типи для кросплатформенної сумісності та безпеки:

#### Базові цілочисельні типи

| Тип | Визначення | Опис |
|-----|------------|------|
| `byte` | `unsigned char` | Байт (8 біт), основний тип для криптографічних даних |
| `word32` | `unsigned int` | 32-бітне беззнакове ціле |
| `word64` | `unsigned long long` | 64-бітне беззнакове ціле |
| `lword` | `word64` | "Large word" — синонім для word64 |

**Файл:** `config_int.h`

#### Integer — арифметика довільної точності

**Файл:** `integer.h`  
**Клас:** `CryptoPP::Integer`

Клас `Integer` реалізує цілі числа довільної точності для криптографічних обчислень (RSA, DH, DSA тощо).

**Основні можливості:**
- Арифметика: `+`, `-`, `*`, `/`, `%`, піднесення до степеня
- Бітові операції: `&`, `|`, `^`, `<<`, `>>`
- Модульна арифметика: `a_exp_b_mod_c()`, `InverseMod()`
- Порівняння: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Конвертація: з/в рядки, байтові масиви

**Конструктори:**

```cpp
Integer();                              // 0
Integer(long value);                    // з числа
Integer(const char *str);               // з рядка "12345" або "0x1A2B"
Integer(RandomNumberGenerator &rng, size_t bitCount);  // випадкове
Integer(RandomNumberGenerator &rng, const Integer &min, const Integer &max);
```

**Ключові методи:**

| Метод | Опис |
|-------|------|
| `BitCount()` | Кількість біт у числі |
| `ByteCount()` | Кількість байт у числі |
| `IsZero()`, `IsNegative()`, `IsEven()`, `IsOdd()` | Перевірки |
| `IsPositive()` | Перевірка на > 0 |
| `Randomize(rng, bitCount)` | Генерація випадкового числа |
| `IsUnit()` | Перевірка чи є одиницею кільця |

**Приклад:**

```cpp
Integer a("123456789012345678901234567890");
Integer b = Integer::Power2(256);  // 2^256
Integer c = a_exp_b_mod_c(a, 65537, b);  // a^65537 mod 2^256
cout << "Bits: " << c.BitCount() << endl;
```

#### SecByteBlock — безпечний буфер

**Файл:** `secblock.h`  
**Клас:** `CryptoPP::SecByteBlock`

Контейнер для криптографічних даних з автоматичним очищенням пам'яті при знищенні (zeroization).

```cpp
SecByteBlock key(32);          // 32 байти, ініціалізовано нулями
rng.GenerateBlock(key, key.size());  // заповнити випадковими
// При виході зі scope — пам'ять автоматично очищується
```

**Переваги над `std::vector<byte>`:**
- Гарантоване очищення при деструкції
- Вирівнювання пам'яті для SIMD операцій (`AlignedSecByteBlock`)

#### RandomNumberGenerator — базовий клас генераторів

**Файл:** `cryptlib.h`  
**Клас:** `CryptoPP::RandomNumberGenerator`

Абстрактний базовий клас для всіх генераторів випадкових чисел.

```cpp
class RandomNumberGenerator : public Algorithm {
public:
    virtual void GenerateBlock(byte *output, size_t size) = 0;
    virtual void IncorporateEntropy(const byte *input, size_t length);
    virtual bool CanIncorporateEntropy() const { return false; }
    
    // Зручні методи
    word32 GenerateWord32(word32 min=0, word32 max=0xFFFFFFFF);
    void GenerateIntoBufferedTransformation(...);
};
```

---

## 2. Генератори псевдовипадкових чисел (ПВЧ)

### 2.1 AutoSeededRandomPool

**Файл:** `osrng.h`  
**Клас:** `CryptoPP::AutoSeededRandomPool`

#### Опис алгоритму

`AutoSeededRandomPool` — головний криптографічно стійкий генератор псевдовипадкових чисел (CSPRNG) бібліотеки Crypto++. Автоматично збирає ентропію з операційної системи при створенні та періодично оновлює внутрішній стан.

**Джерела ентропії на macOS:**
- `/dev/urandom` — ядерний генератор випадкових чисел
- Hardware RNG (раптом у вас є AlphaRNG, OneRNG, TrueRNG)

#### Основні методи

| Метод | Сигнатура | Опис |
|-------|-----------|------|
| `GenerateBlock` | `void GenerateBlock(byte* output, size_t size)` | Генерує `size` випадкових байт |
| `GenerateWord32` | `word32 GenerateWord32(word32 min=0, word32 max=0xFFFFFFFF)` | Генерує 32-бітне число в діапазоні |
| `CanIncorporateEntropy` | `bool CanIncorporateEntropy() const` | Перевіряє можливість додавання ентропії |
| `IncorporateEntropy` | `void IncorporateEntropy(const byte* input, size_t length)` | Додає ентропію до внутрішнього стану |

#### Вхідні дані

- `output` — вказівник на буфер для запису результату
- `size` — кількість байт для генерації
- `min`, `max` — межі діапазону для GenerateWord32

#### Вихідні дані

- Буфер заповнюється криптографічно стійкими випадковими байтами
- GenerateWord32 повертає число у вказаному діапазоні

#### Коди повернення

- Метод `GenerateBlock` не повертає значення (`void`), результат записується в наданий буфер
- При помилці кидає виключення `OS_RNG_Err`

#### Приклад використання

```cpp
#include <cryptopp/osrng.h>
using namespace CryptoPP;

AutoSeededRandomPool rng;

// Генерація 32 випадкових байт
byte buffer[32];
rng.GenerateBlock(buffer, sizeof(buffer));

// Генерація випадкового числа [0, 1000000]
word32 randomNum = rng.GenerateWord32(0, 1000000);

// Додавання додаткової ентропії
byte extraEntropy[] = "additional entropy";
rng.IncorporateEntropy(extraEntropy, sizeof(extraEntropy));
```

---

### 2.2 OS_GenerateRandomBlock

**Файл:** `osrng.h`  
**Функція:** `CryptoPP::OS_GenerateRandomBlock`

#### Опис алгоритму

Пряме звернення до операційної системи для отримання випадкових байт. Читає з `/dev/urandom` для `blocking=false`, інакше з `/dev/random`, але в macOS `/dev/random -> /dev/urandom`, тому без різниці

#### Сигнатура

```cpp
void OS_GenerateRandomBlock(bool blocking, byte* output, size_t size);
```

#### Вхідні дані

| Параметр | Тип | Опис |
|----------|-----|------|
| `blocking` | `bool` | `true` — використовувати `/dev/random` (блокуючий), `false` — `/dev/urandom` (неблокуючий) |
| `output` | `byte*` | Буфер для запису |
| `size` | `size_t` | Кількість байт |

#### Вихідні дані

Буфер заповнюється випадковими байтами безпосередньо від ОС.

#### Коди повернення

- `void` — успішне виконання
- Виключення `OS_RNG_Err` — помилка звернення до ОС

#### Особливості macOS

На macOS обидва режими (blocking/non-blocking) працюють однаково, оскільки `/dev/random` і `/dev/urandom` є символічними посиланнями на один і той самий генератор.

#### Приклад

```cpp
byte osRandom[32];
OS_GenerateRandomBlock(false, osRandom, sizeof(osRandom));
```

---

### 2.3 Hash_DRBG

**Файл:** `drbg.h`  
**Клас:** `CryptoPP::Hash_DRBG<HASH, STRENGTH, SEEDLENGTH>`

#### Опис алгоритму

Детермінований генератор випадкових бітів (DRBG) на основі хеш-функції відповідно до стандарту **NIST SP 800-90A**.

**Принцип роботи:**
1. Ініціалізація внутрішнього стану V та константи C з seed
2. Генерація: `output = Hash(V || counter)`
3. Оновлення стану: `V = (V + output + C) mod 2^seedlen`

#### Параметри шаблону

| Параметр | Опис | Типові значення |
|----------|------|-----------------|
| `HASH` | Хеш-функція | `SHA256`, `SHA512` |
| `STRENGTH` | Рівень безпеки (байти) | 128, 256 |
| `SEEDLENGTH` | Довжина seed (біти) | 440 |

**Важливо:** `MINIMUM_ENTROPY = STRENGTH`, тобто мінімальний seed = 128 байт для STRENGTH=128. При виклику функції перевіряється розмір послідовності для ентропії, і функція повертає помилку якщо ENTROPY < STRENGTH

#### Основні методи

| Метод | Сигнатура | Опис |
|-------|-----------|------|
| `IncorporateEntropy` | `void IncorporateEntropy(const byte* input, size_t length)` | Ініціалізація/reseed |
| `GenerateBlock` | `void GenerateBlock(byte* output, size_t size)` | Генерація випадкових байт |

#### Властивості

- **Детермінованість:** однаковий seed → однакова послідовність
- **Reseed interval:** рекомендується після 2^48 запитів

#### Приклад

```cpp
#include <cryptopp/drbg.h>
#include <cryptopp/sha.h>

Hash_DRBG<SHA256, 128, 440> drbg;

// Ініціалізація seed (55 bytes = 440 bits)
byte seed[55];
OS_GenerateRandomBlock(false, seed, sizeof(seed));
drbg.IncorporateEntropy(seed, sizeof(seed));

// Генерація
byte output[32];
drbg.GenerateBlock(output, sizeof(output));
```

---

### 2.4 HMAC_DRBG

**Файл:** `drbg.h`  
**Клас:** `CryptoPP::HMAC_DRBG<HASH, STRENGTH, SEEDLENGTH>`

#### Опис алгоритму

Детермінований генератор на основі HMAC відповідно до **NIST SP 800-90A**.

**Принцип роботи:**
1. Ініціалізація: K = 0x00..., V = 0x01...
2. Update: `K = HMAC(K, V || 0x00 || seed)`, `V = HMAC(K, V)`
3. Generate: `V = HMAC(K, V)`, output = V

#### Приклад

```cpp
HMAC_DRBG<SHA256, 128, 440> hmacDrbg;
hmacDrbg.IncorporateEntropy(seed, sizeof(seed));

byte output[32];
hmacDrbg.GenerateBlock(output, sizeof(output));
```

---

## 3. Перевірка на простоту

### 3.1 IsPrime

**Файл:** `nbtheory.h`  
**Функція:** `CryptoPP::IsPrime`

#### Опис алгоритму

Перевірка числа на простоту за допомогою тесту Міллера-Рабіна з попередньою перевіркою ділимості на малі прості.

#### Сигнатура

```cpp
bool IsPrime(const Integer &p);
```

#### Вхідні дані

- `p` — число для перевірки (`Integer`)

#### Вихідні дані

- `true` — число ймовірно просте
- `false` — число складене

#### Приклад

```cpp
#include <cryptopp/nbtheory.h>
#include <cryptopp/integer.h>

Integer n("1000000007");
if (IsPrime(n)) {
    // n ймовірно просте
}
```

---

### 3.2 RabinMillerTest

**Файл:** `nbtheory.h`  
**Функція:** `CryptoPP::RabinMillerTest`

#### Опис алгоритму

Імовірнісний тест Міллера-Рабіна для перевірки простоти.

**Алгоритм:**
1. Представити n-1 = 2^s × d, де d непарне
2. Для кожного раунду вибрати випадкове a ∈ [2, n-2]
3. Обчислити x = a^d mod n
4. Якщо x = 1 або x = n-1, перейти до наступного раунду
5. Повторити s-1 разів: x = x² mod n, якщо x = n-1, перейти до наступного раунду
6. Якщо не знайдено n-1, число складене

#### Сигнатура

```cpp
bool RabinMillerTest(RandomNumberGenerator &rng, const Integer &n, unsigned int rounds);
```

#### Вхідні дані

| Параметр | Тип | Опис |
|----------|-----|------|
| `rng` | `RandomNumberGenerator&` | Генератор для вибору свідків |
| `n` | `const Integer&` | Число для перевірки |
| `rounds` | `unsigned int` | Кількість раундів тесту |

#### Вихідні дані

- `true` — число пройшло всі раунди (ймовірно просте)
- `false` — знайдено свідка складеності (точно складене)

#### Імовірність помилки

| Раунди | Імовірність помилки |
|--------|---------------------|
| 10 | ≤ 2^(-20) ≈ 10^(-6) |
| 20 | ≤ 2^(-40) ≈ 10^(-12) |
| 50 | ≤ 2^(-100) ≈ 10^(-30) |

#### Приклад

```cpp
AutoSeededRandomPool rng;
Integer n("104729");  // просте

bool result = RabinMillerTest(rng, n, 20);
// result == true з імовірністю помилки < 10^(-12)
```

---

## 4. Генерація простих чисел та ключів

### 4.1 PrimeAndGenerator

**Файл:** `nbtheory.h`  
**Функція:** `CryptoPP::PrimeAndGenerator`

#### Опис алгоритму

Генерує **безпечне просте** p таке, що p = 2q + 1, де q також просте, та знаходить генератор g підгрупи порядку q.

**Застосування:** параметри для DSA, Diffie-Hellman, ElGamal.

#### Сигнатура

```cpp
void PrimeAndGenerator(RandomNumberGenerator &rng, 
                       Integer &p, Integer &q, Integer &g, 
                       unsigned int pbits);
```

#### Вхідні дані

| Параметр | Тип | Опис |
|----------|-----|------|
| `rng` | `RandomNumberGenerator&` | Генератор випадкових чисел |
| `pbits` | `unsigned int` | Бажана довжина p в бітах |

#### Вихідні дані

| Параметр | Опис |
|----------|------|
| `p` | Безпечне просте число |
| `q` | Просте q = (p-1)/2 |
| `g` | Генератор підгрупи порядку q |

#### Приклад

```cpp
AutoSeededRandomPool rng;
Integer p, q, g;

PrimeAndGenerator(rng, p, q, g, 2048);

// Перевірка
assert(IsPrime(p));
assert(IsPrime(q));
assert(p == 2*q + 1);
```

---

### 4.2 RSA Key Generation

**Файл:** `rsa.h`  
**Клас:** `CryptoPP::RSA::PrivateKey` (базується на `InvertibleRSAFunction`)

#### Опис алгоритму

Генерація пари ключів RSA:
1. Генерація двох великих простих p, q однакової довжини
2. Обчислення n = p × q
3. Обчислення φ(n) = (p-1)(q-1)
4. Вибір публічної експоненти e = 65537 (стандартне значення)
5. Обчислення d = e^(-1) mod φ(n)
6. Обчислення CRT параметрів: dp, dq, qInv

#### Основні методи

| Метод | Сигнатура | Опис |
|-------|-----------|------|
| `GenerateRandomWithKeySize` | `void GenerateRandomWithKeySize(RNG &rng, unsigned int keySize)` | Генерація ключа заданого розміру |
| `Validate` | `bool Validate(RNG &rng, unsigned int level)` | Перевірка коректності ключа |
| `GetModulus` | `const Integer& GetModulus()` | Отримати n |
| `GetPublicExponent` | `const Integer& GetPublicExponent()` | Отримати e |
| `GetPrivateExponent` | `const Integer& GetPrivateExponent()` | Отримати d |
| `GetPrime1`, `GetPrime2` | `const Integer& GetPrime1()` | Отримати p, q |

#### Рівні валідації

| Рівень | Перевірки |
|--------|-----------|
| 1 | Базові: e > 1, d > 1, n > 1 |
| 2 | + перевірка e×d ≡ 1 (mod φ(n)) |
| 3 | + перевірка простоти p, q |

#### Приклад

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

AutoSeededRandomPool rng;

// Генерація 2048-bit RSA ключа
RSA::PrivateKey privateKey;
privateKey.GenerateRandomWithKeySize(rng, 2048);

// Валідація
if (!privateKey.Validate(rng, 3)) {
    throw runtime_error("Key validation failed");
}

// Отримання публічного ключа
RSA::PublicKey publicKey(privateKey);

// Параметри
const Integer& n = privateKey.GetModulus();
const Integer& e = privateKey.GetPublicExponent();
```

---

## 5. Результати тестування

### 5.1 Продуктивність генераторів ПВЧ

| Генератор | Швидкість (1 MB) | Примітки |
|-----------|------------------|----------|
| AutoSeededRandomPool | ~200 MB/s | Найшвидший |
| HMAC_DRBG<SHA256> | ~37 MB/s | Детермінований |
| Hash_DRBG<SHA256> | ~19 MB/s | Детермінований |

### 5.2 Час генерації простих чисел (safe primes)

| Розмір | Час генерації |
|--------|---------------|
| 512 біт | ~25-30 ms |
| 1024 біт | ~2-3 s |

### 5.3 Час генерації RSA ключів

| Розмір ключа | Час генерації |
|--------------|---------------|
| 2048 біт | ~50-100 ms |

