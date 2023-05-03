import json
import os
import csv

tacticas={"initial-access":"TA0001","execution":"TA0002","persistence":"TA0003","privilege-escalation":"TA0004","defense-evasion":"TA0005","credential-access":"TA0006","discovery":"TA0007","lateral-movement":"TA0008","collection":"TA0009","exfiltration":"TA0010","command-and-control":"TA0011","impact":"TA0040","resource-development":"TA0042","reconnaissance":"TA0043"}

path="C:/Users/fedsola/Desktop/FEDSOLA/MITRE" #cambiar el path por el de una carpeta que contenga todas subcarpetas con versiones

# Leemos el archivo JSON

def calcularTacticaId(unaTactica):
    if unaTactica in tacticas:
        codigo = tacticas[unaTactica]
    else:
        codigo = "Unknown"
    return codigo
    
    


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
                    ttp_id = str(datos["objects"][0]['external_references'][0]['external_id'])
                    nombre = str(datos['objects'][0]['name'])
                    
                    if "." in ttp_id:
                        #es una subtecnica
                        subtecnicaTit = nombre #ya que mitre no diferencia
                        subtecnicaId= ttp_id
                        tecnicaId= ttp_id.split(".")[0]
                        tecnicaTit="" #TO DO

                    else:
                        #es una tecnica
                        tecnicaTit=nombre
                        tecnicaId= ttp_id
                        subtecnicaId=""
                        subtecnicaTit=""
                    
                    deprecated = "FALSE"
                    # Revisamos campo de Revoked si existe.
                    try:
                        revoked = datos['objects'][0]['revoked'] # true o false
                        if revoked:
                            deprecated="TRUE"
                    # creo que está demás pero bueno lo agrego.
                    except: 
                        deprecated = "FALSE"
                    
                    try:
                        tacticas = datos['objects'][0]['kill_chain_phases'] # lista de tacticas 
                        #por cada tactica de la lista
                        for unaTactica in tacticas:
                            tacticaDes = str(unaTactica["phase_name"])
                            lista_ttps.append({'Version':version,'Tactica':tacticaDes,'TacticaID':calcularTacticaId(tacticaDes),'Tecnica':tecnicaTit,'TecnicaID':tecnicaId,'Subtecnica':subtecnicaTit,'SubtecnicaID':subtecnicaId, 'Deprecated':deprecated})
                    # otro caso de deprecated: cuando no tiene tactica asignada.
                    except: 
                        lista_ttps.append({'Version':version,'Tactica':"N/A",'TacticaID': "N/A",'Tecnica':tecnicaTit,'TecnicaID':tecnicaId,'Subtecnica':subtecnicaTit,'SubtecnicaID':subtecnicaId, 'Deprecated':"TRUE"})
                    
                    
                    
                        
    return lista_ttps

lista=calcularTTPs(path)

print(lista)

# Completamos los valores de "Tecnica" en la lista
for elemento in lista:
    tecnicaIdActual = elemento['TecnicaID']
    tecnicaActual = elemento['Tecnica']
    if tecnicaActual == "":
        # Buscamos otros valores en la lista que tengan el mismo "TecnicaID"
        for x in lista:
            if x['TecnicaID'] == tecnicaIdActual and x['Tecnica']!= "":
                elemento['Tecnica'] = x['Tecnica']

# Abrimos un archivo CSV para escribir los datos
with open('ttps.csv', mode='w', newline='') as file:
    writer = csv.writer(file)

    # Escribimos la primera fila del archivo CSV
    writer.writerow(['Version', 'Tactica', 'TacticaID', 'Tecnica','TecnicaID','Subtecnica','SubtecnicaID','Deprecated'])

    # Escribimos cada TTP en el archivo CSV
    for ttp in lista:
        writer.writerow([ttp['Version'], ttp['Tactica'], ttp['TacticaID'], ttp['Tecnica'], ttp['TecnicaID'], ttp['Subtecnica'], ttp['SubtecnicaID'], ttp['Deprecated']])
