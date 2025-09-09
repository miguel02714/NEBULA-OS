
teste = {
    "teste":"teste1"
}

valor = input(str('Digite uma mensagem:> '))
def calculo():
    if valor > 1:
        valor1 = print('o valor e 1')
    elif valor > 2:
        valor1 = print('o valor e 2')
    elif valor > 3:
        valor1 = print('o valor e 3')
    elif valor > 4:
        valor1 = print('o valor e 4')
    elif valor > 5:
        valor1 = print('o valor e 5')
    elif valor > 6:
        valor1 = print('o valor e 6')
    elif valor > 7:
        valor1 = print('o valor e 7')
    elif valor > 8:
        valor1 = print('o valor e 8')
    elif valor > 9:
        valor1 = print('o valor e 9')
    return valor1

print (f'{cal}')

from flask import Flask, request

app = Flask(__name__)



# todas as defs


def number_of_characters_per_word():
    valor = input("Digite uma mensagem:> ")
    palavras = valor.split()

    print("\n📏 Número de caracteres por palavra:")
    for i, palavra in enumerate(palavras, start=1):
        qtd_caracteres = len(palavra)
        vezes_dois = qtd_caracteres * 2
        binario = bin(vezes_dois)[2:]  # remove o '0b' do início

        print(f"Palavra {i}: '{palavra}' → {qtd_caracteres} caracteres, vezes dois = {vezes_dois}, binário = {binario}")


number_of_characters_per_word()

@app.route('/teste')
def teste():
    return (number_of_characters_per_word())
