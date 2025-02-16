# Developer: Gustavo Rosas
# Profile: https://www.linkedin.com/in/gustavorosas-/
# Version: 1.0

# Define o encoding para UTF-8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
[Console]::InputEncoding = [Text.Encoding]::UTF8

# Define a configuração regional para UTF-8
$env:LANG = "pt_BR.UTF-8"

# Altera a página de código para UTF-8
chcp 65001 | Out-Null

##############################################################################################
#                                   VERIFICAÇÕES INICIAIS                                    #
##############################################################################################

# Verifica se o módulo Active Directory está instalado
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "O módulo Active Directory não está instalado. Instale-o antes de continuar." -ForegroundColor Red
    exit  # Se o módulo não estiver instalado, o script é interrompido
}

##############################################################################################
#                                          FUNÇÕES                                           #
##############################################################################################

# Função para exibir o banner
function ExibirBanner {
    Clear-Host
    Write-Host @"
               
     .d8888b.                    888                    880        d8888 8888888b.  
    d88P  Y88b                   888                    880       d88888 888  "Y88b 
    888    888                   888                    880      d88P888 888    888 
    888         .d88b.  88888b.  888888 888d888 .d88b.  880     d88P 888 888    888 
    888        d88""88b 888 "88b 888    888P"  d88""88b 880    d88P  888 888    888 
    888    888 888  888 888  888 888    888    888  888 880   d88P   888 888    888 
    Y88b  d88P Y88..88P 888  888 Y88b.  888    Y88..88P 880  d8888888888 888  .d88P 
     "Y8888P"   "Y88P"  888  888  "Y888 888     "Y88P"  880 d88P     888 8888888P" 

"@ -ForegroundColor Cyan
    Write-Host "    Desevolvedor: Gustavo Rosas" -ForegroundColor DarkGray
    Write-Host "    LinkedIn: linkedin.com/in/gustavorosas-/`n`n" -ForegroundColor DarkGray
}

function DefinirDominio {
    # Exibe o banner
    ExibirBanner

    # Loop para garantir que o domínio seja válido e completo
    while ($true) {
        # Solicita ao administrador o domínio que será utilizado
        $global:dominioEscolhido = Read-Host "Digite o domínio completo que deseja gerenciar (exemplo: teste.com)"

        # Validação simples (caso não tenha sido inserido um domínio)
        if (-not $dominioEscolhido) {
            Write-Host "Domínio não fornecido. Por favor, tente novamente." -ForegroundColor Red
            continue
        }

        # Verifica se o domínio está no formato FQDN (contém pelo menos um ponto)
        if ($dominioEscolhido -notmatch "\.") {
            Write-Host "Por favor, insira o domínio completo (FQDN), como 'teste.com'." -ForegroundColor Red
            continue
        }

        # Tenta verificar se o domínio é válido
        try {
            $dominioValido = Get-ADDomain -Identity $dominioEscolhido -ErrorAction Stop
            Write-Host "Domínio selecionado: $dominioEscolhido" -ForegroundColor Green
            break  # Sai do loop se o domínio for válido
        } catch {
            Write-Host "Domínio '$dominioEscolhido' não encontrado ou inválido. Por favor, tente novamente." -ForegroundColor Red
        }
    }

    # Limpa a tela após a seleção do domínio
    Clear-Host
}

function ListarUsuarios {
    # O cmdlet Get-ADUser com o parâmetro -Filter * traz todos os usuários e seus status de habilitação
    # Select-Object é usado para selecionar as colunas que queremos exibir
    # Format-Table organiza os dados em uma tabela
    Get-ADUser -Filter * -Properties Enabled -Server $dominioEscolhido | Select-Object Name, SamAccountName, Enabled | Format-Table
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."  # Solicita que o usuário pressione uma tecla
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")  # Aguarda o usuário pressionar uma tecla
}

function ListarGrupos {
    Write-Host "Listando grupos no domínio $dominioEscolhido..." -ForegroundColor Yellow
    try {
        # Lista todos os grupos no domínio especificado
        Get-ADGroup -Filter * -Server $dominioEscolhido | 
            Select-Object Name, GroupScope, GroupCategory | 
            Format-Table -AutoSize
    } catch {
        Write-Host "Erro ao listar grupos: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function ListarComputadores {
    Write-Host "Listando computadores no domínio $dominioEscolhido..." -ForegroundColor Yellow
    try {
        # Lista todos os computadores no domínio
        Get-ADComputer -Filter * -Server $dominioEscolhido | 
            Select-Object Name, OperatingSystem, LastLogonDate | 
            Format-Table -AutoSize
    } catch {
        Write-Host "Erro ao listar computadores: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function CriarUsuario {
    # Solicita ao administrador o nome do novo usuário
    $nome = Read-Host "Digite o nome do usuário"
    
    # Solicita o sobrenome, mas torna-o opcional
    $sobrenome = Read-Host "Digite o sobrenome do usuário"

    # Se o sobrenome não for fornecido, atribui uma string vazia
    if (-not $sobrenome) {
        $sobrenome = ""
    }

    # Cria o nome de usuário (SamAccountName), tratando o caso de o sobrenome ser vazio
    if ($sobrenome) {
        $usuario = "$nome.$sobrenome"
    } else {
        $usuario = $nome
    }

    # Loop para garantir que a senha atenda aos pré-requisitos
    while ($true) {
        # Solicita a senha do usuário de forma segura
        $senha = Read-Host "Digite a senha do usuário" -AsSecureString

        # Converte SecureString para String para a verificação
        $senhaEmTexto = [System.Net.NetworkCredential]::new("", $senha).Password

        # Verifica se a senha atende aos pré-requisitos
        $senhaValida = VerificarPreRequisitosSenha -senha $senhaEmTexto -usuario $usuario -dominio $dominioEscolhido

        if ($senhaValida) {
            # Se a senha for válida, sai do loop
            break
        } else {
            Write-Host "A senha não atende aos pré-requisitos. Por favor, tente novamente." -ForegroundColor Red
        }
    }

    try {
        # Usa o cmdlet New-ADUser para criar o novo usuário no Active Directory
        New-ADUser -Name $usuario `
                   -GivenName $nome `
                   -Surname $sobrenome `
                   -SamAccountName $usuario `
                   -UserPrincipalName "$usuario@$dominioEscolhido" `
                   -AccountPassword $senha `
                   -Enabled $true

        # Informa que o usuário foi criado com sucesso
        Write-Host "Usuário $usuario criado com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao criar o usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function DeletarUsuario {
    # Solicita ao administrador o nome do usuário a ser deletado
    $usuario = Read-Host "Digite o nome do usuário a ser deletado"

    # Confirmação antes de deletar o usuário
    $confirmacao = Read-Host "Tem certeza que deseja deletar o usuário $usuario? (S/N)"

    if ($confirmacao -eq 'S') {
        # Usa o cmdlet Remove-ADUser para deletar o usuário do AD
        Remove-ADUser -Identity ${usuario} -Confirm:$false -Server $dominioEscolhido

        # Informa que o usuário foi deletado com sucesso
        Write-Host "Usuário ${usuario} deletado com sucesso!" -ForegroundColor Green
    }
    else {
        Write-Host "Operação cancelada. O usuário não foi deletado." -ForegroundColor Yellow
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function DesativarUsuario {
    # Solicita ao administrador o nome do usuário a ser inativado
    $usuario = Read-Host "Digite o nome do usuário a ser inativado"

    # Confirmação antes de inativar o usuário
    $confirmacao = Read-Host "Tem certeza que deseja inativar o usuário $usuario? (S/N)"

    if ($confirmacao -eq 'S') {
        # Usa o cmdlet Disable-ADAccount para desabilitar a conta do usuário
        Disable-ADAccount -Identity ${usuario} -Server $dominioEscolhido

        # Informa que a conta foi desativada com sucesso
        Write-Host "Usuário ${usuario} inativado com sucesso!" -ForegroundColor Green
    }
    else {
        Write-Host "Operação cancelada. O usuário não foi inativado." -ForegroundColor Yellow
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function AtivarUsuario {
    # Solicita o nome do usuário a ser reativado
    $usuario = Read-Host "Digite o nome do usuário a ser reativado"

    # Solicita confirmação para reativar o usuário
    $confirmacao = Read-Host "Tem certeza que deseja reativar o usuário ${usuario} (S/N)"

    # Se o usuário confirmar, prossegue com a reativação
    if ($confirmacao -eq "S") {
        # Verifica se o usuário existe no Active Directory
        $usuarioAD = Get-ADUser -Identity ${usuario} -ErrorAction SilentlyContinue
        if ($usuarioAD) {
            # Define uma senha temporária que atenda aos requisitos de complexidade
            $senhaTemporaria = ConvertTo-SecureString "SenhaTemporaria123!" -AsPlainText -Force

            # Verifica se a senha temporária atende aos pré-requisitos
            $senhaValida = VerificarPreRequisitosSenha -senha "SenhaTemporaria123!" -usuario ${usuario} -dominio $dominioEscolhido

            if ($senhaValida) {
                # Ativa a conta do usuário e redefine a senha
                Enable-ADAccount -Identity ${usuario} -Server $dominioEscolhido
                Set-ADAccountPassword -Identity ${usuario} -NewPassword $senhaTemporaria -Reset

                # Informa que a conta foi reativada com sucesso
                Write-Host "Usuário ${usuario} reativado com sucesso!" -ForegroundColor Green
            } else {
                Write-Host "A senha temporária não atende aos pré-requisitos. A conta não foi reativada." -ForegroundColor Red
            }
        } else {
            # Caso o usuário não exista
            Write-Host "Usuário ${usuario} não encontrado no Active Directory!" -ForegroundColor Red
        }
    } else {
        Write-Host "Reativação cancelada." -ForegroundColor Yellow
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function ResetarSenha {
    # Solicita ao administrador o nome de usuário para o qual a senha será resetada
    $usuario = Read-Host "Digite o nome de usuário para resetar a senha"

    # Verifica se o usuário existe no Active Directory
    $usuarioExistente = Get-ADUser -Filter {SamAccountName -eq $usuario} -ErrorAction SilentlyContinue

    if (-not $usuarioExistente) {
        Write-Host "Usuário ${usuario} não encontrado!" -ForegroundColor Red
        return
    }

    # Solicita a nova senha do administrador
    $novaSenha = Read-Host "Digite a nova senha" -AsSecureString

    # Converte SecureString para String para a verificação
    $senhaEmTexto = [System.Net.NetworkCredential]::new("", $novaSenha).Password

    # Verifica se a senha atende aos pré-requisitos
    $senhaValida = VerificarPreRequisitosSenha -senha $senhaEmTexto -usuario ${usuario} -dominio $dominioEscolhido

    if ($senhaValida) {
        # Reseta a senha do usuário no Active Directory
        Set-ADAccountPassword -Identity ${usuario} -NewPassword $novaSenha -Reset -Server $dominioEscolhido
        Write-Host "Senha do usuário ${usuario} resetada com sucesso!" -ForegroundColor Green
    } else {
        Write-Host "Senha não atende aos pré-requisitos. A senha não foi resetada." -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function VerificarPreRequisitosSenha {
    param(
        [string]$senha,
        [string]$usuario,
        [string]$dominio
    )

    # Defina os requisitos de complexidade
    $minLength = 7  # O comprimento mínimo é 7 caracteres
    $complexidadeRegex = '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])'  # A senha deve atender à complexidade

    # Verifica o comprimento
    if ($senha.Length -lt $minLength) {
        Write-Host "Senha muito curta. A senha precisa ter pelo menos $minLength caracteres." -ForegroundColor Red
        return $false
    }

    # Verifica a complexidade
    if ($senha -notmatch $complexidadeRegex) {
        Write-Host "Senha não atende aos requisitos de complexidade. Ela deve conter pelo menos uma letra maiúscula, uma letra minúscula, um número e um caractere especial." -ForegroundColor Red
        return $false
    }

    # Verifica se a senha contém o nome do usuário ou o domínio
    if ($senha -match $usuario -or $senha -match $dominio) {
        Write-Host "A senha não pode conter o nome de usuário ou o domínio." -ForegroundColor Red
        return $false
    }

    Write-Host "Senha válida!" -ForegroundColor Green
    return $true
}

function BloquearUsuario {
    $usuario = Read-Host "Digite o nome do usuário a ser bloqueado"

    # Bloqueia o usuário no Active Directory
    try {
        Set-ADUser -Identity $usuario -Enabled $false -Server $dominioEscolhido
        Write-Host "Usuário $usuario bloqueado com sucesso!" -ForegroundColor Green

        # Aguarda que o usuário pressione uma tecla para voltar ao menu
        Write-Host "`nPressione qualquer tecla para voltar ao menu..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    } catch {
        Write-Host "Erro ao bloquear o usuário $usuario. Verifique se o nome do usuário está correto." -ForegroundColor Red
    }
}

function DesbloquearUsuario {
    $usuario = Read-Host "Digite o nome do usuário a ser desbloqueado"

    # Verifica se o usuário existe no domínio
    $usuarioAD = Get-ADUser -Identity $usuario -ErrorAction SilentlyContinue

    if ($usuarioAD) {
        # Verifica se o usuário está bloqueado
        if ($usuarioAD.Enabled -eq $false) {
            try {
                # Tenta desbloquear o usuário
                Enable-ADAccount -Identity $usuario -Server $dominioEscolhido
                Write-Host "O usuário $usuario foi desbloqueado com sucesso!" -ForegroundColor Green
            } catch {
                # Caso ocorra um erro de senha inadequada
                if ($_ -match "The password does not meet the length, complexity, or history requirement") {
                    Write-Host "Erro: A senha do usuário $usuario não atende aos requisitos de complexidade ou comprimento do domínio." -ForegroundColor Red
                    Write-Host "Você deve resetar a senha do usuário antes de desbloqueá-lo." -ForegroundColor Red

                    # Chama a função para resetar a senha
                    ResetarSenha
                    # Após o reset de senha, tenta novamente desbloquear o usuário
                    Enable-ADAccount -Identity $usuario -Server $dominioEscolhido
                    Write-Host "O usuário $usuario foi desbloqueado com sucesso após redefinir a senha!" -ForegroundColor Green
                } else {
                    Write-Host "Erro ao desbloquear o usuário $usuario. Erro: $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "O usuário $usuario já está desbloqueado." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Erro ao desbloquear o usuário $usuario. Verifique se o nome do usuário está correto." -ForegroundColor Red
    }

    # Pausa para voltar ao menu
    Read-Host "`nPressione qualquer tecla para voltar ao menu..."
}

function SincronizarAD {
    Write-Host "Iniciando sincronização do Active Directory..." -ForegroundColor Yellow
    try {
        # Força a sincronização do AD
        Sync-ADObject -Object (Get-ADDomainController -DomainName $dominioEscolhido -Discover -Service PrimaryDC).HostName
        Write-Host "Sincronização do Active Directory concluída com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao sincronizar o Active Directory: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function CriarNovoGrupo {
    # Solicita o nome do novo grupo
    $nomeGrupo = Read-Host "Digite o nome do novo grupo"

    # Valida o escopo do grupo (Global, Universal, DomainLocal)
    $escopoGrupo = ""
    while ($escopoGrupo -notin @("Global", "Universal", "DomainLocal")) {
        $escopoGrupo = Read-Host "Digite o escopo do grupo (Global, Universal, DomainLocal)"
        if ($escopoGrupo -notin @("Global", "Universal", "DomainLocal")) {
            Write-Host "Opção inválida! Por favor, escolha entre Global, Universal ou DomainLocal." -ForegroundColor Red
        }
    }

    # Valida o tipo do grupo (Security ou Distribution)
    $tipoGrupo = ""
    while ($tipoGrupo -notin @("Security", "Distribution")) {
        $tipoGrupo = Read-Host "Digite o tipo do grupo (Security ou Distribution)"
        if ($tipoGrupo -notin @("Security", "Distribution")) {
            Write-Host "Opção inválida! Por favor, escolha entre Security ou Distribution." -ForegroundColor Red
        }
    }

    # Verifica se a variável $dominioEscolhido está definida
    if (-not $dominioEscolhido) {
        Write-Host "Erro: A variável \$dominioEscolhido não foi definida." -ForegroundColor Red
        return
    }

    try {
        # Cria o novo grupo no domínio especificado
        New-ADGroup -Name $nomeGrupo `
                    -GroupScope $escopoGrupo `
                    -GroupCategory $tipoGrupo `
                    -Server $dominioEscolhido
        Write-Host "Grupo $nomeGrupo criado com sucesso no domínio $dominioEscolhido!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao criar o grupo: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function AdicionarUsuarioAGrupo {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    # Solicita o nome do grupo
    $grupo = Read-Host "Digite o nome do grupo"

    try {
        # Adiciona o usuário ao grupo
        Add-ADGroupMember -Identity $grupo -Members ${usuario} -Server $dominioEscolhido
        Write-Host "Usuário ${usuario} adicionado ao grupo $grupo com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao adicionar usuário ao grupo: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function RemoverUsuarioDeGrupo {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    # Solicita o nome do grupo
    $grupo = Read-Host "Digite o nome do grupo"

    try {
        # Remove o usuário do grupo
        Remove-ADGroupMember -Identity $grupo -Members ${usuario} -Server $dominioEscolhido -Confirm:$false
        Write-Host "Usuário ${usuario} removido do grupo $grupo com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao remover usuário do grupo: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function VerificarMembrosDeGrupo {
    # Solicita o nome do grupo
    $grupo = Read-Host "Digite o nome do grupo"

    try {
        # Lista os membros do grupo
        $membros = Get-ADGroupMember -Identity $grupo -Server $dominioEscolhido |
            Select-Object Name, SamAccountName, ObjectClass
        if ($membros) {
            Write-Host "Membros do grupo ${grupo}:" -ForegroundColor Yellow
            $membros | Format-Table -AutoSize
        } else {
            Write-Host "O grupo $grupo não possui membros." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Erro ao listar membros do grupo: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function MoverObjetoParaOU {
    # Solicita o nome do objeto (usuário, computador, etc.)
    $objeto = Read-Host "Digite o nome do objeto (SamAccountName)"

    # Solicita o nome da OU de destino
    $ouDestino = Read-Host "Digite o DistinguishedName da OU de destino (ex: OU=Usuarios,DC=aluno,DC=hacker,DC=com)"

    try {
        # Move o objeto para a OU de destino
        Move-ADObject -Identity $objeto -TargetPath $ouDestino -Server $dominioEscolhido
        Write-Host "Objeto $objeto movido para a OU $ouDestino com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao mover o objeto: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function AlterarAtributosUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    # Exibe os atributos atuais do usuário
    try {
        $usuarioAD = Get-ADUser -Identity ${usuario} -Properties * -Server $dominioEscolhido
        Write-Host "Atributos atuais do usuário ${usuario}:" -ForegroundColor Yellow
        $usuarioAD | Select-Object Name, GivenName, Surname, TelephoneNumber, EmailAddress | Format-Table -AutoSize
    } catch {
        Write-Host "Erro ao buscar informações do usuário: $_" -ForegroundColor Red
        return
    }

    # Solicita novos valores para os atributos
    $novoNome = Read-Host "Digite o novo nome (ou pressione Enter para manter o atual)"
    $novoSobrenome = Read-Host "Digite o novo sobrenome (ou pressione Enter para manter o atual)"
    $novoTelefone = Read-Host "Digite o novo telefone (ou pressione Enter para manter o atual)"
    $novoEmail = Read-Host "Digite o novo e-mail (ou pressione Enter para manter o atual)"

    try {
        # Atualiza os atributos do usuário
        Set-ADUser -Identity ${usuario} `
                   -GivenName $(if ($novoNome) { $novoNome } else { $usuarioAD.GivenName }) `
                   -Surname $(if ($novoSobrenome) { $novoSobrenome } else { $usuarioAD.Surname }) `
                   -TelephoneNumber $(if ($novoTelefone) { $novoTelefone } else { $usuarioAD.TelephoneNumber }) `
                   -EmailAddress $(if ($novoEmail) { $novoEmail } else { $usuarioAD.EmailAddress }) `
                   -Server $dominioEscolhido
        Write-Host "Atributos do usuário ${usuario} atualizados com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao atualizar atributos do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function StatusUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca o status do usuário no domínio especificado
        $usuarioAD = Get-ADUser -Identity ${usuario} -Properties Enabled -Server $dominioEscolhido -ErrorAction Stop

        # Verifica o status e exibe com a cor correspondente
        Write-Host -NoNewline "Status do usuário ${usuario}: "
        if ($usuarioAD.Enabled) {
            Write-Host "Habilitado" -ForegroundColor Green
        } else {
            Write-Host "Desabilitado" -ForegroundColor Red
        }
    } catch {
        Write-Host "Erro ao buscar status do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function SIDUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca o SID do usuário no domínio especificado
        $usuarioAD = Get-ADUser -Identity ${usuario} -Properties SID -Server $dominioEscolhido -ErrorAction Stop
        Write-Host "SID do usuário ${usuario}: $($usuarioAD.SID)" -ForegroundColor Yellow
    } catch {
        Write-Host "Erro ao buscar SID do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function MembrosUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca os grupos dos quais o usuário é membro
        $grupos = Get-ADPrincipalGroupMembership -Identity ${usuario} -Server $dominioEscolhido -ErrorAction Stop |
            Select-Object Name, GroupScope, GroupCategory
        if ($grupos) {
            Write-Host "Grupos dos quais o usuário ${usuario} é membro:" -ForegroundColor Yellow
            $grupos | Format-Table -AutoSize
        } else {
            Write-Host "O usuário ${usuario} não é membro de nenhum grupo." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Erro ao buscar grupos do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function CaminhoOUUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca o caminho da OU do usuário
        $usuarioAD = Get-ADUser -Identity ${usuario} -Properties DistinguishedName -Server ${dominioEscolhido} -ErrorAction Stop
        $ou = $usuarioAD.DistinguishedName -replace '^CN=[^,]+,', ''
        Write-Host "Caminho da OU do usuário ${usuario}: $ou" -ForegroundColor Yellow
    } catch {
        Write-Host "Erro ao buscar caminho da OU do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function ValidadeContaUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca a data de validade da conta do usuário
        $usuarioAD = Get-ADUser -Identity $usuario -Properties AccountExpirationDate -Server $dominioEscolhido -ErrorAction Stop
        if ($usuarioAD.AccountExpirationDate) {
            Write-Host "Validade da conta do usuário ${usuario}: $($usuarioAD.AccountExpirationDate)" -ForegroundColor Yellow
        } else {
            Write-Host "A conta do usuário $usuario não tem data de expiração definida." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Erro ao buscar validade da conta do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "Pressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function UltimoResetUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca a data do último reset de senha do usuário
        $usuarioAD = Get-ADUser -Identity $usuario -Properties PasswordLastSet -Server $dominioEscolhido -ErrorAction Stop
        Write-Host "Último reset de senha do usuário ${usuario}: $($usuarioAD.PasswordLastSet)" -ForegroundColor Yellow
    } catch {
        Write-Host "Erro ao buscar último reset de senha do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "Pressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function UltimoLogonUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca a data do último logon do usuário
        $usuarioAD = Get-ADUser -Identity $usuario -Properties LastLogonDate -Server $dominioEscolhido -ErrorAction Stop
        if ($usuarioAD.LastLogonDate) {
            Write-Host "Último logon do usuário ${usuario}: $($usuarioAD.LastLogonDate)" -ForegroundColor Yellow
        } else {
            Write-Host "O usuário $usuario nunca fez logon." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Erro ao buscar último logon do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "Pressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function DataExpiracaoSenhaUsuario {
    # Solicita o nome do usuário
    $usuario = Read-Host "Digite o nome do usuário (SamAccountName)"

    try {
        # Busca a data de expiração da senha do usuário
        $usuarioAD = Get-ADUser -Identity $usuario -Properties msDS-UserPasswordExpiryTimeComputed -Server $dominioEscolhido -ErrorAction Stop
        $expiraSenha = [datetime]::FromFileTime($usuarioAD.'msDS-UserPasswordExpiryTimeComputed')
        Write-Host "Data de expiração da senha do usuário ${usuario}: $expiraSenha" -ForegroundColor Yellow
    } catch {
        Write-Host "Erro ao buscar data de expiração da senha do usuário: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "Pressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function ExportarRelatorioUsuarios {
    # Solicita o caminho e nome do arquivo CSV
    $caminhoArquivo = Read-Host "Digite o caminho e nome do arquivo CSV para exportar (ex: C:\RelatorioUsuarios.csv)"

    try {
        # Busca todos os usuários no domínio
        $usuarios = Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, EmailAddress, LastLogonDate -Server $dominioEscolhido |
            Select-Object Name, SamAccountName, Enabled, EmailAddress, LastLogonDate

        # Exporta os dados para um arquivo CSV
        $usuarios | Export-Csv -Path $caminhoArquivo -NoTypeInformation
        Write-Host "Relatório de usuários exportado com sucesso para $caminhoArquivo!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao exportar relatório de usuários: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function ExportarRelatorioComputadores {
    # Solicita o caminho e nome do arquivo CSV
    $caminhoArquivo = Read-Host "Digite o caminho e nome do arquivo CSV para exportar (ex: C:\RelatorioComputadores.csv)"

    try {
        # Busca todos os computadores no domínio
        $computadores = Get-ADComputer -Filter * -Properties Name, OperatingSystem, LastLogonDate -Server $dominioEscolhido |
            Select-Object Name, OperatingSystem, LastLogonDate

        # Exporta os dados para um arquivo CSV
        $computadores | Export-Csv -Path $caminhoArquivo -NoTypeInformation
        Write-Host "Relatório de computadores exportado com sucesso para $caminhoArquivo!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao exportar relatório de computadores: $_" -ForegroundColor Red
    }

    # Aguarda que o usuário pressione uma tecla para voltar ao menu
    Write-Host "`nPressione qualquer tecla para voltar ao menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

##############################################################################################
#                               MENU PRINCIPAL | CATEGORIAS                                  #
##############################################################################################


function MenuPrincipal {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "        MENU DE GERENCIAMENTO AD              " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "Domínio Atual: $dominioEscolhido" -ForegroundColor Green
    Write-Host "---------------------------------------------" -ForegroundColor Gray
    Write-Host "1 - Gerenciamento de Usuários"
    Write-Host "2 - Gerenciamento de Grupos"
    Write-Host "3 - Gerenciamento de Computadores"
    Write-Host "4 - Relatórios e Exportação"
    Write-Host "5 - Outras Operações"
    Write-Host "0 - Sair" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma categoria
    $categoria = Read-Host "`nDigite o número correspondente à categoria desejada"

    # A estrutura switch é usada para chamar o menu da categoria escolhida
    switch ($categoria) {
        1 { MenuUsuarios }
        2 { MenuGrupos }
        3 { MenuComputadores }
        4 { MenuRelatorios }
        5 { MenuOutrasOperacoes }
        0 {
            Clear-Host
            exit
        }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}


##############################################################################################
#                                   SUBMENUS | OPÇÕES                                        #
##############################################################################################


function MenuUsuarios {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "          GERENCIAMENTO DE USUÁRIOS          " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Listar usuários"
    Write-Host "2 - Criar usuário"
    Write-Host "3 - Deletar usuário"
    Write-Host "4 - Desativar usuário"
    Write-Host "5 - Ativar usuário"
    Write-Host "6 - Resetar senha"
    Write-Host "7 - Bloquear usuário"
    Write-Host "8 - Desbloquear usuário"
    Write-Host "9 - Alterar atributos de um usuário"
    Write-Host "10 - Status do usuário"
    Write-Host "11 - SID do usuário"
    Write-Host "12 - Membros do usuário"
    Write-Host "13 - Caminho da OU do usuário"
    Write-Host "14 - Validade de conta do usuário"
    Write-Host "15 - Último reset do usuário"
    Write-Host "16 - Último logon do usuário"
    Write-Host "17 - Data de expiração da senha do usuário"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { ListarUsuarios }
        2 { CriarUsuario }
        3 { DeletarUsuario }
        4 { DesativarUsuario }
        5 { AtivarUsuario }
        6 { ResetarSenha }
        7 { BloquearUsuario }
        8 { DesbloquearUsuario }
        9 { AlterarAtributosUsuario }
        10 { StatusUsuario }
        11 { SIDUsuario }
        12 { MembrosUsuario }
        13 { CaminhoOUUsuario }
        14 { ValidadeContaUsuario }
        15 { UltimoResetUsuario }
        16 { UltimoLogonUsuario }
        17 { DataExpiracaoSenhaUsuario }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------------------------------

function MenuGrupos {
    Clear-Host  # Limpa a tela antes de exibir o menu
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "          GERENCIAMENTO DE GRUPOS            " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Listar grupos"
    Write-Host "2 - Criar novo grupo"
    Write-Host "3 - Adicionar usuário a um grupo"
    Write-Host "4 - Remover usuário de um grupo"
    Write-Host "5 - Verificar membros de um grupo"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { ListarGrupos }
        2 { CriarNovoGrupo }
        3 { AdicionarUsuarioAGrupo }
        4 { RemoverUsuarioDeGrupo }
        5 { VerificarMembrosDeGrupo }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------------------------------

function MenuComputadores {
    Clear-Host  # Limpa a tela antes de exibir o menu
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "        GERENCIAMENTO DE COMPUTADORES        " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Listar computadores"
    Write-Host "2 - Mover computador para outra OU"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { ListarComputadores }
        2 { MoverObjetoParaOU }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------------------------------

function MenuRelatorios {
    Clear-Host  # Limpa a tela antes de exibir o menu
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "           RELATÓRIOS E EXPORTAÇÃO           " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Exportar relatório de usuários"
    Write-Host "2 - Exportar relatório de computadores"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { ExportarRelatorioUsuarios }
        2 { ExportarRelatorioComputadores }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------------------------------

function MenuRelatorios {
    Clear-Host  # Limpa a tela antes de exibir o menu
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "           RELATÓRIOS E EXPORTAÇÃO           " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Exportar relatório de usuários"
    Write-Host "2 - Exportar relatório de computadores"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { ExportarRelatorioUsuarios }
        2 { ExportarRelatorioComputadores }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------------------------------

function MenuOutrasOperacoes {
    Clear-Host  # Limpa a tela antes de exibir o menu
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "              OUTRAS OPERAÇÕES               " -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1 - Sincronizar AD"
    Write-Host "99 - Voltar ao menu principal" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Cyan

    # Lê a entrada do usuário para selecionar uma opção
    $opcao = Read-Host "`nDigite o número correspondente à opção desejada"

    Clear-Host

    # A estrutura switch é usada para executar diferentes funções conforme a opção escolhida
    switch ($opcao) {
        1 { SincronizarAD }
        99 { MenuPrincipal }
        default { Write-Host "Opção inválida!" -ForegroundColor Red }
    }
}

##############################################################################################
#                                       LOOP PRINCIPAL                                       #
##############################################################################################


# Chama a função para definir o domínio antes de exibir o menu
DefinirDominio

# Loop do menu: o script ficará em execução, exibindo o menu repetidamente até o usuário sair
while ($true) {
    MenuPrincipal
}