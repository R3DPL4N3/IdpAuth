# OpenIddict Opaque Token Authentication

Bu proje, OpenIddict kullanarak opaque token (reference token) authentication akışını gösterir.

## Proje Yapısı

- **openiddictapi**: Authorization Server (OpenIddict)
- **webassemblyclient**: Blazor WebAssembly Client
- **clientsapi**: Resource Server (Protected API)

## Gereksinimler

- .NET 10.0
- Docker Desktop (SQL Server için)

## Kurulum

### 1. Docker SQL Server'ı Başlat

```bash
docker-compose up -d
```

Veya manuel olarak:

```bash
docker run -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=YourStrong@Passw0rd" -p 1433:1433 --name idptest-sqlserver -d mcr.microsoft.com/mssql/server:2022-latest
```

### 2. Projeleri Çalıştır

Sırayla şu projeleri çalıştırın:

1. **OpenIddict API** (https://localhost:7179)
2. **Clients API** (https://localhost:7101)
3. **WebAssembly Client** (https://localhost:7121)

## Test Kullanıcı Bilgileri

- **Username**: `testuser`
- **Password**: `Test123!`

## Akış

1. WebAssembly client, OpenIddict API'den authorization code alır
2. Authorization code ile token exchange yapılır ve opaque token alınır
3. WebAssembly client, Clients API'ye istek yaparken opaque token'ı gönderir
4. Clients API, token'ı OpenIddict API'nin introspection endpoint'inde doğrular
5. Doğrulama başarılıysa, protected resource döner

## Notlar

- İlk çalıştırmada veritabanı otomatik olarak oluşturulur
- Test client ve kullanıcı otomatik olarak seed edilir
- Connection string'i `appsettings.json` dosyasından değiştirebilirsiniz
