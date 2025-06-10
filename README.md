# Generador de Claves Seguras API

Una API REST construida con FastAPI para generar diferentes tipos de claves seguras.

## Características

- Generación de contraseñas seguras personalizables
- Generación de tokens aleatorios
- Generación de API keys
- Generación de claves de encriptación

## Instalación

1. Clona este repositorio
2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

Para iniciar el servidor:
```bash
uvicorn key_generator_api:app --reload
```

La API estará disponible en `http://localhost:8000`

## Endpoints

### 1. Generar Contraseña
```
GET /generate/password
```
Parámetros:
- length: Longitud de la contraseña (8-128)
- include_uppercase: Incluir mayúsculas (true/false)
- include_numbers: Incluir números (true/false)
- include_special: Incluir caracteres especiales (true/false)

### 2. Generar Token
```
GET /generate/token
```
Parámetros:
- length: Longitud del token en bytes (16-128)

### 3. Generar API Key
```
GET /generate/api-key
```
Parámetros:
- prefix: Prefijo para la API key (default: "sk")
- length: Longitud de la parte aleatoria en bytes (16-64)

### 4. Generar Clave de Encriptación
```
GET /generate/encryption-key
```

## Documentación

La documentación interactiva está disponible en:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`