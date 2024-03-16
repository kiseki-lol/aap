# AAP

Aya Asset Packer ... for آپ!

`$ ./AAP <private_key_pem_file_path> <resource_folder_path> <output_aap_file_path>`

Requirements of resource folder:

- `content` folder
- `PlatformContent` folder
- `shaders` folder
- `AppSettings.xml`

Output AAP file structure:

- 5 byte magic header (`0x61 0x61 0x70 0x25 0x25`)
- 128 byte SHA256 signature of all incoming data
- `uint16_t` representing size of incoming `AppSettings.xml` in bytes
- `AppSettings.xml` encoded in msgpack format
- `uint64_t` representing size of incoming archive containing the asset folders in bytes
- tar archive compressed with zstd containing asset folders

## License

Copyright (c) Kiseki 2024. All rights reserved. Not for public use.
