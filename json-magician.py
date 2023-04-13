import json
import os
import csv
path="C:/Users/feseijo/Desktop/MITRE" #cambiar el path por el de una carpeta que contenga todas subcarpetas con sus respectivas versiones
#En el ejemplo de arriba, MITRE es la carpeta madre que debería tener subcarpetas del estilo cti-ATT-CK-v1.0, cti-ATT-CK-v2.0 y asi

# Leemos el archivo JSON

def calcularTTPs(path_main):
    lista_ttps=[]
    folders = os.listdir(path_main)
    print(folders)
    #Buscamos abrir cada carpeta de version
    for folder_name in folders: 
        folder_path = path_main+'/'+folder_name #Obtenemos el path de la carpeta
        print(folder_path)
        if os.path.isdir(folder_path): #si es una carpeta
            print(folder_name.split("v")[1])
            version = folder_name.split("-v")[1] #Obtengo version en base a nombre de la carpeta
           
            #leemos todos los archivos de la carpeta actual
            #with open(folder_path+'/'+"enterprise-attack/attack-pattern/", 'rb') as folder_current:

            folder_current= folder_path+'/'+"enterprise-attack/attack-pattern"
            archivos = os.listdir(folder_current)
                
            #por cada archivo obtenemos las ttps
            for file_name in archivos:
                with open(os.path.join(folder_current,file_name),'rb') as file_current:
                    datos = json.load(file_current)
                    
                    #Extraemos los elementos que nos interesan
                   
                    tecnicaId = str(datos["objects"][0]['external_references'][0]['external_id'])
                    tecnicaTit = str(datos['objects'][0]['name'])
                    tacticas = datos['objects'][0]['kill_chain_phases'] #lista de tacticas 
                    
                    #por cada tactica de la lista
                    for unaTactica in tacticas:
                        tacticaDes = str(unaTactica["phase_name"])
                        lista_ttps.append({'Version': version, 'Tactica':tacticaDes, 'ID':tecnicaId, 'Tecnica': tecnicaTit})
                    
    return lista_ttps

lista=calcularTTPs(path)
print(lista)


# Abrimos un archivo CSV para escribir los datos
with open('ttps.csv', mode='w', newline='') as file:
    writer = csv.writer(file)

    # Escribimos la primera fila del archivo CSV
    writer.writerow(['Version', 'Tactica', 'ID', 'Tecnica'])

    # Escribimos cada TTP en el archivo CSV
    for ttp in lista:
        writer.writerow([ttp['Version'], ttp['Tactica'], ttp['ID'], ttp['Tecnica']])

