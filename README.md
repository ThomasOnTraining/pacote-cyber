# pacote-cyber
uma extensão tampermonkey com varias funções de uteis para cyber security

# Visão Geral e Funcionalidades Principais
O script cria um painel flutuante na página (ativado pelo botão 'C' no canto inferior direito) que intercepta todo o tráfego de rede — tanto requisições HTTP/Fetch quanto mensagens de WebSockets.

# A interface é dividida em três guias principais: Requests, WebSockets e Ferramentas.

## Guia Requests
Esta é a guia principal para interagir com o tráfego HTTP.

Interceptação e Visualização:

Todas as requisições fetch e XMLHttpRequest (XHR) que a página faz são listadas em tempo real.

Você pode ver o método (GET, POST, etc.) e a URL de cada requisição.

Ao clicar em uma requisição, um editor de código com realce de sintaxe mostra os detalhes completos da requisição, incluindo URL, método, cabeçalhos e corpo (body). Isso facilita a leitura e edição.

Manipulação e Reenvio:

Reenviar Original: Clicar neste botão faz com que a requisição seja enviada novamente, exatamente como a original.

Reenviar Modificado: Você pode editar qualquer parte da requisição (URL, cabeçalhos ou corpo) no editor e reenviá-la com as modificações. Isso é perfeito para testar o comportamento do servidor com dados diferentes, como um ID alterado ou um token inválido.

Ferramentas Úteis:

Copiar cURL: Gera e copia o comando cURL da requisição para a área de transferência. Isso permite que você a execute no seu terminal ou em outras ferramentas, como o Postman.

Copiar Payload: Copia apenas o corpo da requisição, ideal para quando você quer testar a mesma carga útil (payload) em diferentes lugares.

Ferramentas de Ataque: Este painel é a grande novidade. Ele permite automatizar o envio de requisições:

Loop de Requisições: Você pode configurar um intervalo de tempo (em milissegundos) e enviar a mesma requisição repetidamente, útil para testes de estresse ou de taxa de limite (rate limiting).

Injeção de Payloads: Essa é a funcionalidade mais avançada. Você pode carregar um arquivo de texto com uma lista de payloads (por exemplo, payloads para SQL Injection, XSS, etc.). O script, então, envia a requisição em loop, substituindo uma string INJECT_HERE no corpo da requisição por cada payload da sua lista. Isso automatiza a busca por vulnerabilidades.

## Guia WebSockets
Esta guia é dedicada a monitorar e manipular o tráfego de WebSockets.

Visualização de Mensagens:

Lista todas as mensagens enviadas e recebidas via WebSockets em tempo real.

Você consegue ver a direção da mensagem (enviada ou recebida) e o conteúdo.

Reenviar Mensagens:

Ao selecionar uma mensagem, você pode editá-la e reenviá-la para o servidor. Isso é útil para testar a validação de mensagens do servidor ou simular eventos específicos.

## Guia Ferramentas
Esta guia oferece utilitários adicionais para análise de segurança.

Decodificador de JWT:

Cole qualquer token JWT neste campo. O script irá automaticamente decodificar e mostrar o cabeçalho (header) e o payload do token, facilitando a análise de tokens de autenticação.

Editor de Cookies:

Lista todos os cookies da página atual.

Você pode editar os valores de um cookie ou até mesmo excluí-los. As alterações são aplicadas instantaneamente. No entanto, é importante recarregar a página para que a aplicação use os novos valores.

Análise de Segurança Passiva (Rodapé)
O painel no rodapé do script oferece uma visão passiva da segurança da página.

Cookies da Página: Mostra todos os cookies definidos e indica se eles são seguros (secure) ou não. Cookies inseguros podem ser um vetor de ataque.

Scripts Externos: Lista todos os scripts que a página carrega de domínios externos. Ficar de olho nisso é crucial, pois um script de terceiros malicioso pode comprometer a segurança da sua aplicação.
