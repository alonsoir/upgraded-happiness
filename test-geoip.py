# Test rápido de geolocalización
try:
    import geoip2.database
    import geoip2.webservice

    print("✅ geoip2 disponible")

    # Probar con base de datos local
    try:
        with geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            response = reader.city('104.199.65.9')
            print(f"✅ IP geolocalizada: {response.location.latitude}, {response.location.longitude}")
    except:
        print("❌ Base de datos local no disponible en /usr/share/GeoIP/GeoLite2-City.mmdb")
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city('104.199.65.9')
            print(f"✅ IP geolocalizada: {response.location.latitude}, {response.location.longitude}")
    except:
        print("❌ Base de datos local no disponible")

except ImportError:
    print("❌ geoip2 no instalado: pip install geoip2")