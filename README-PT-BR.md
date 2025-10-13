# framesniff

Uma ferramenta de linha de comando para exploração e análise de redes, com foco em captura e manipulação de frames em diferentes camadas e padrões de comunicação (Wi-Fi (IEEE 802.11 / DLT_IEEE802_11_RADIO), Ethernet (IEEE 802.3 / DLT10MB), Bluetooth HCI / DLT_BLUETOOTH_HCI_4). Projetada para permitir uma análise profunda de protocolos de rede sem e fio, assim como a exploração dos dispositivos e frames transmitidos pelos eles.

O foco atual está no desenvolvimento para suporte do padrão IEEE 802.11. Bluetooth e ethernet ainda não são suportados.

## Licença
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## Visão geral

framesniff permite:

* Capturar frames aplicando filtros de armazenamento e exibição.
* Realizar scan em modo station ou monitor (com channel hopping opcional).
* Gerar arquivos compatíveis com hashcat (formato `22000`) a partir de JSON contendo dados EAPOL/PMKID.
* Converter pacotes ou frames hexadecimais brutos em pcap.
* Enviar frames brutos (hex) por uma interface.

## Principais funcionalidades atualmente

* `set-monitor <ifname>` / `set-station <ifname>` — alternar modo da interface.
* `scan-monitor` — scan em modo monitor em tempo real com suporte a channel hopping.
* `sniff <ifname>` — capturar frames com opções de DLT, filtros, contagem, timeout, salvamento em JSON entre outras opções.
* `generate-22000` — converter JSON (EAPOL/PMKID) em arquivo `hashcat.22000`.
* `hextopcap` — gerar um arquivo pcap a partir de JSON contendo pacotes em hexadecimal bruto.
* `send-raw <ifname>` — enviar frames/packets em hexadecimal bruto por uma interface.

## Formatos suportados / DLTs

* `DLT_IEEE802_11_RADIO` — frames 802.11 com header radiotap.
* `EN10MB` — Ethernet (pcap linktype EN10MB).
* `DLT_BLUETOOTH_HCI_H4` — Bluetooth HCI (H4).

## Requisitos

* Sistema operacional: Linux.
* Permissões: Muitas operações exigem privilégios de root (captura em modo monitor, alteração de modo de interface, envio de frames).
* Python 3.13.
* Ferramentas opcionais para inspeção dos resultados (ex.: Wireshark/tshark) para abrir arquivos pcap gerados se necessário.

## Instalação (sugestão)

1. Clonar o repositório:

```bash
git clone https://github.com/gusprojects008/framesniff/framesniff.git
cd framesniff
```
Veja as funcionalidades que o programa fornece:

```bash
python framesniff.py --help
```
2. Exemplo de ataque de brute force offline em MICs (Message Integrity Code) de frames EAPOL de redes WPA2-Personal. 

## Aviso Legal
***Por favor, utilize essas técnicas e conhecimentos passados em ambientes controlados onde você possui autorização para atuar, seja para estudo, exploração, desenvolvimento, ou até, apenas para matar a curiosidade. Não me responsabilizo pelo mal uso da ferramenta, ela foi e está sendo desenvolvida estritamente para fins educaionais e profissionais.
E é sério, é BEM mais fácil pedir a senha ao dono da rede, ou trabalhar (de preferencia honestamente) e conseguir dinheiro para contratar um ISP (Internet Service Provider), do que passar horas estudando e gastando recursos computacionais para apenas obter a senha da rede (PSK) mas sem nehuma pretensão a mais.***

- ### 🧠 Veja meu blog sobre como funcionam as redes Wi-Fi e meu mapa mental sobre os principais métodos de ataque a redes Wi-Fi
  - [Como funcionam as redes sem fio](https://gustavoaraujo.pages.dev/blogs/como-funcionam-as-comunica%C3%A7oes-sem-fio)
  - [Mapas mentais sobre redes Wi-Fi](https://github.com/gusprojects008/mapas-mentais/blob/main/markdowns/ataques-redes-wifi.md)

**Após começar o sniff na frequência dos alvos, é recomendado enviar alguns frames de deauthentication (desautenticação) para redes ou dispositivos que não possuam PMF (Protection Management Frames) ativo, para isso, é recomendado que antes que você capture qualquer frame de deauthentication por meio do sniff do programa ou do wireshark, e abra o conteúdo hexadecimal do frame em um editor de texto ou editor hexadecimal, e utilize o hextopcap para converte-lo para pcap e assim poder se aberto e visualizado pelo wireshark, e por meio do hexdump do wireshark, percorrer os campos e modificar os caracteres hexadecimais do frame de acordo com a correspondência do hexdump do wireshark. Para assim, configura-lo para ser de acordo com o bssid do AP Alvo e MAC do dispositvo alvo.**

***
Visualize informações mais detalhadas de cada frame (incluindo o conteúdo hexadecimal bruto de cada um) após a captura feita pela operação de scan-monitor ou sniff.
Verifique as informações de vendor specific, para mais informações sobre o AP, inclusive números de versão, modelo e UUID, com essas e outras informações é possível buscar mais informações sobre o dispositivo, e até mesmo exploits em alguns casos.
***

Alternar para monitor:

```bash
sudo python framesniff.py set-monitor wlan0
```
Scan in monitor mode (with TUI and hopping):

**Will display all nearby APs and devices, with real-time updates, including their associations.**

***Pay attention and check the WPS status. If enabled (YES), see more information about the WPS configuration in the scan-monitor output file, which will be saved after the program closes. Press ctrl+s or F12 to save the information captured by the TUI (Text User Interface). Depending on the supported WPS operating modes, it is possible to brute force remote numbers and, in a short period of time (2 to 8 hours), discover the PSK (Pre-Shredded Key). Tools like [bully](https://github.com/kimocoder/bully) can do this, but in some cases, the AP may enter a complete blocking mode for WPS authentication, only to return to normal after a few hours.***

```bash
sudo python framesniff.py scan-monitor wlan0 --dlt DLT_IEEE802_11_RADIO --hopping-interval 5.0 --bands 2.4
```
After detecting and obtaining information from the AP(s) and target device(s), configure the monitor interface to the same frequency or channel as the AP (WPA2-Personal) and target device.

```bash
sudo python framesniff.py set-frequency wlan0 2417
```
Capture EAPOL frames (sniff):

```bash
sudo python framesniff sniff wlan0 --dlt DLT_IEEE802_11_RADIO --store-filter "mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol" --display-filter "mac_hdr, body" -o eapol-frames-attack.json
```

Generate hashcat file 22000:

***If you analyze the captured EAPOL frames and identify the PMKID (usually in EAPOL frame 1), you can use it to bruteforce faster. For more details see the generate-22000 help.***

```bash
python framesniff.py generate-22000 --bitmask 2 --ssid MyNetwork --input eapol-frames-attack.json --output hashcat.22000
hashcat -m 22000 hashcat.22000 wordlist.txt --show
```
---

Other usage options:

Convert JSON hex to pcap:

```bash
python framesniff.py hextopcap --dlt DLT_IEEE802_11_RADIO -i raw_packets.json -o output.pcap
```

Send raw frames:

```bash
sudo python framesniff.py send-raw wlan0 -i raw_packets.json --count 10 --interval 0.5
```
## JSON file structure — examples

### `send-raw` / `hextopcap` — input format

```json
{ 
"raw": [ 
"00112233445566aabbccddeeff...", 
"dead beef..." 
]
}
```

### `generate-22000` — bitmask 1 (PMKID)

```json
{ 
"ap_mac": "aa:bb:cc:dd:ee:ff", 
"sta_mac": "11:22:33:44:55:66"
"pmkid": "e4f3... (32 hex chars)", 
}
```

### `generate-22000` — bitmask 2 (raw EAPOL messages)

```json
{ 
"raw": [ 
"0103005f02030a...", 
"0103005f02030a..." 
]
}
```
---

## IDEIAS E IMPLEMENTAÇÕES FUTURAS

Esta seção contém alguns insights que obtive durante o desenvolvimento, mas não há certeza de que serão implementados; eles precisam ser revisados e mais estudos são necessários para decidir se serão implementados na prática.

* A captura no modo monitor será feita apenas a partir de soquetes brutos; a análise, a descriptografia, etc., serão feitas a partir de payloads LLC. Em outras palavras, o sniff ocorrerá apenas no modo monitor. E não sei se irei implementar opção para captura em camadas específicas l3, l4, l7, pois acho que complicaria algumas outras funções e o próposito do programa.
* Opção para o usuário enviar quadros criptografados corretamente para que o AP possa recebê-los.
* Permitir que o usuário forneça um arquivo JSON com as informações necessárias para descriptografar quadros protegidos, informações como:
`{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}` — isso para redes WPA2 PSK. Ainda seria necessário estudar e ver como isso funcionaria para redes WPA3 e outros modos WPA2/WPA3, como corporativo, etc.
* Função que permite ao usuário realizar o salto de canal em uma faixa de canais específica; o usuário pode definir quais canais não serão usados ou pode passar bandas específicas (0 para 2,4 GHz, 1 para 5 GHz, 2 para 2,4 GHz e 5 GHz) e, assim, passar os canais que não serão usados.
* Com `createpkt`, permite ao usuário modificar e construir um quadro/pacote a partir de modelos fornecidos, ou modificar uma sequência ou um pacote específico de um arquivo JSON contendo todos os pacotes hexadecimais brutos que deseja editar `{"raw": ["12345abcef", "12345abcef"]}` e abri-lo na interface gráfica de edição de pacotes. O usuário poderá salvar um pacote específico que esteja editando ou todos os que estava editando; Para isso, ele sempre poderá escolher o nome do arquivo de saída onde o(s) pacote(s) hexadecimal(is) bruto(s) será(ão) gravado(s). O formato desses arquivos finais será:
`{"identificador exclusivo desse pacote ou quadro específico": "", "raw": "0123456789101112131415abcdef"}`.
* `pcaptohex` pega cada quadro bruto de um arquivo pcap e grava seu conteúdo hexadecimal bruto em um arquivo `.json` que pode ser usado pelo programa.
* Funções básicas para manipulação de interface sem a necessidade de `iw`, utilizando o módulo `wnlpy`, que está em desenvolvimento.
* Possivelmente remover a função de salto de canal de `monitor-scan` e torná-la independente; ou seja, o usuário teria que chamá-la separadamente, podendo assim, fazer um configuração mais robusta.
* Na função de salto de canal, permitir que o usuário defina a largura do canal.
* Pensar no que fazer em casos de interfaces monitor virtuais.
* Instruir os usuários sobre o padrão para expressões de filtragem. Recomendo capturar frames com a função `sniff` e, em seguida, analisar o resultado JSON.
* Com base nas funções que forneço, instruir as formas e possibilidades de uso; por exemplo: analisar frames capturados com o Wireshark por meio da função `hextopcap` (para converter frames capturados com framesniff para pcap), ou capturar frames brutos com `sniff` e usar a função `send-frames` para reenviar todos os frames brutos capturados, sendo assim possível regenerar/simular o tráfego capturado anteriormente.
* Utilizar o GitHub docs.

---

## O QUE ESTÁ FALTANDO? CORRIGIR/ADICIONAR

* Analisar todos os parâmetros marcados (o máximo possível).
* Análise completa das informações do país.
* Análise completa dos recursos de RM.
* Análise completa das informações de ERP e TIM.
* Análise completa para recursos estendidos.
* Formatar tabelas de AP e clientes em tabelas reais.
* Analisar os recursos dos parâmetros corrigidos.
* Corrigir as funções `set_frequency` e de salto de canal.
* Refatorar todos os analisadores para incluir TODOS os dados analisados, incluindo valores, tags, comprimentos, etc., tudo o que está no quadro ou pacote, não apenas as informações relevantes.
* Revisar os analisadores e suas saídas.
* Implementar módulo para geração/edição de quadros/pacotes.
* Adicionar mais verificações para detecção de erros.
* Tornar as mensagens de erro mais rastreáveis e fáceis de usar.
* Usar mais registros para mensagens de operação.
* Revisar todo o código.
* Revisar a operação de todos os recursos e verificar se estão funcionando corretamente.
* Desenvolver uma interface TUI para o sniff, que será semelhante ao tshark.
* Desenvolver uma interface TUI para o createpkt.
* Melhorar o argparse no quadro sniff.py, usando o tipo, etc.
* Deixar verificações de segurança em pontos críticos do programa.
* Adicionar vídeos e imagens na documentação.
* Corrgir parser de mac header.
