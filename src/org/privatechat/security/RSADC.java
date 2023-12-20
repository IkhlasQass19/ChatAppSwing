/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.privatechat.security;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class RSADC {
	
	private BigInteger n,e,d; // (e,n) cl� public, (d,n) cl� priv�
	private int taillecle, blocsize;

        public RSADC() {
                
        }
        
        public void initial(int taillecle,BigInteger e,BigInteger n){
                this.taillecle=taillecle;
                this.e=e;
                this.n=n;
                BigInteger bi = this.e.modPow(this.e, this.n);
		this.blocsize = bi.toByteArray().length - 10;           
        }
        
	public RSADC(int taillecle){
		this.taillecle = taillecle;
		
		BigInteger p, q;
		
		p = new BigInteger(1, new Random()).probablePrime(taillecle/2, new Random());	//p grand premier 
		q  = new BigInteger(1, new Random()).probablePrime(taillecle/2, new Random());	//q grand premier
		
		this.n = p.multiply(q);	//n = p*q	le nombre de bits de n donne la taille de la cl� 
		

		BigInteger p2 = p.subtract(new BigInteger("1"));	//p2 = p-1
		BigInteger q2 = q.subtract(new BigInteger("1"));	//q2 = q-1
		BigInteger w = p2.multiply(q2);						//w = (p-1)*(q-1) 
		
		this.e = new BigInteger(taillecle + 1 , new Random()); // e aleatoire > p, q
		
		while ((!this.e.gcd(w).toString().equals("1")) || (this.e.compareTo(w) != -1 )){ // e premier avec w et e < w
			this.e = new BigInteger(taillecle + 1, new Random());
		}
		
		this.d = this.e.modInverse(w);	// calcul du modulo inverse � e pour avoir la cl� priv�e (cf algorithme d'euclide etendu) 
		
		//On applique le chiffrement une fois pour avoir une id�e du nombre de byte que l'on peut mettre par bloc
		//Ce nombre doit etre inferieur a n sinon l'operation de chiffrement et de dechiffrement n'est plus valable
		//Par exemple n = 1073, e = 73, d = 649 si l'on chiffre 72 (72^73 mod 1073) on obtient 997
		//lorsque l'on dechiffre 997^649 mod 1073 = 72 l'algorithme fonctionne, maintenant prenons
		// 1075 ^73 mod 1073 = 224 lors du dechiffrement : 224^649 mod 1073 = 2 on obtient pas le meme nombre
		//Vous pouvez tester cela par vous meme en changeant le -10 par +1
		BigInteger bi = this.e.modPow(this.e, this.n);
		this.blocsize = bi.toByteArray().length - 10;	//On aura donc des blocs toujours inferieur � n
	}
	
	/**
	 * Permet d'initialiser le premier �l�ment de la cl� public
	 * @param e
	/* 
	public void setE(String e){
		this.e = new BigInteger(e);
		BigInteger bi = this.e.modPow(this.e, this.n);
		this.blocsize = bi.toByteArray().length - 10;
	}
	
	
	 * Permet d'initialiser le deuxieme �l�ment des cl�s (modulo)
	 * @param n
	
	public void setN(String n){
		this.n = new BigInteger(n);
		BigInteger bi = this.e.modPow(this.e, this.n);
		this.blocsize = bi.toByteArray().length - 10;
	}
	
	
	 Permet d'initialiser le premier element de la cl� priv�e
	  @param d
	 
	public void setD(String d){
		this.d = new BigInteger(d);
		BigInteger bi = this.e.modPow(this.e, this.n);
		this.blocsize = bi.toByteArray().length - 10;
	}*/
	
/* ***************************************************************************************
 * Fonction de chiffrement et de dechiffrement
 * ****************************************************************************************/
	/**
	 * Permet de chiffrer un tableau de byte
	 */
	public byte[] chiffrer(byte mess[]){
		//On utilise un ArrayList car la taille de sortie est diff�rent de la taille d'entr�e et n'est pas connue a l'avance
		ArrayList<Byte> lst = new ArrayList<>();	
		byte res[] = null;	
		BigInteger bi;
		byte size[];
		byte bloc[] = new byte[blocsize];
		byte newbloc[] = null;
		int i = 0;
		
		//On ajoute au debut de la liste la taille du message d�chiffr� car dans le chiffrement par bloc
		//on complete avec des 0 et de ce fait la taille du messages dechiffr� n'est pas forcement la taille d'origine
		size = intToBytes(mess.length);
		lst.add(0, size[0]);lst.add(1, size[1]);lst.add(2, size[2]);lst.add(3, size[3]);
		
		while ( i < mess.length){
			//On cr�e un bloc de donn�e ainsi une analyse de fr�quence ou une recherche exhaustive
			//� partir de la cl� publique est inutile de ce fait il est obligatoire de connaitre la cl� secrete
			//ou de faire une factorisation de la cl� publique pour retrouver la cl� priv�e ce qui est tr�s long
			for (int j = 0; j<this.blocsize;j++){
				if (i+j < mess.length){
					bloc[j] = mess[i+j];
				}else{
					bloc[j] = 0;			//Si on a d�pass� le nombre de byte du message alors on complete avec des 0
				}
			}
			bi = new BigInteger(bloc);	//Ce bloc est convertis en BigInteger
			bi = bi.modPow(this.e, this.n);			//On applique le chiffrement
			newbloc = bi.toByteArray();			//On convertit en tableau de byte
			size = intToBytes(newbloc.length);	//On convertit la taille du tableau en 4 byte
			lst.add(size[0]);lst.add(size[1]);lst.add(size[2]);lst.add(size[3]);	//On ajoute la taille a liste de sortie
			for (int j = 0; j<newbloc.length;j++)
				lst.add(newbloc[j]);		//On ajoute les bytes du chiffr� a la liste
			i += blocsize;
		}
		
		int lstsize = lst.size();
		res = new byte[lstsize];
		for (i=0; i<lstsize; i++)
			res[i] = lst.get(i);		//On met la liste dans un tableau avant de retourner le resultat

		return res;
	}
	
	/**
	 * Cette fonction permet de dechiffrer des messages
	 */
	public byte[] dechiffrer(byte mess[]){
		byte res[]= null;
		ArrayList<Byte> lst = new ArrayList<>();
		BigInteger bi;
		int i=0;
		byte newbloc[] = null;
		byte tmpsize[] = new byte[4];
		int size, initsize, newsize;
		
		//On recupere la taille initiale du message
		tmpsize[0] = mess[0];tmpsize[1] = mess[1];tmpsize[2] = mess[2];tmpsize[3] = mess[3];
		initsize = bytesToInt(tmpsize);
		i = 4;
		
		while (i<mess.length){
			tmpsize[0] = mess[i];	//On recupere les 4 bytes contenant taille du BigInteger a dechiffrer
			tmpsize[1] = mess[i+1];
			tmpsize[2] = mess[i+2];
			tmpsize[3] = mess[i+3];
			i+=4;
			size = bytesToInt(tmpsize);		//On convertit les 4 bytes en un entier
			newbloc = new byte[size];		
			for (int j =0;j<size;j++)	
				newbloc[j] = mess[i+j];			//On recupere les bytes qui compose le BigInteger � dechiffrer
			bi = new BigInteger(newbloc);			//Ce bloc est convertis en BigInteger
			bi = bi.modPow(d, n);			//On applique le chiffrement
			newbloc = bi.toByteArray();		//On recupere les bytes dechiffr�
			newsize = newbloc.length;
			for (int j=0;j<newsize;j++)
				lst.add(newbloc[j]);		//On ajoute les bytes a la liste
			i+= size;
		}
		res=new byte[initsize];
		for (i=0;i<initsize;i++){	//On convertit la liste en tableau avant de retourner le resultat
			res[i] = lst.get(i);
		}
		return res;
	}

	public BigInteger getN(){
		return n;
	}

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public int getTaillecle() {
        return taillecle;
    }

    public void setTaillecle(int taillecle) {
        this.taillecle = taillecle;
    }

    public int getBlocsize() {
        return blocsize;
    }

/* ***************************************************************************************
     * Fonction d'obtention des cl�s
     * ****************************************************************************************/
    /**
     * Obtention du couple de cl� public
     */
    public void setBlocsize(int blocsize) {
        this.blocsize = blocsize;
    }

/* ***************************************************************************************
     * Fonction g�n�rale priv�e utilis� dans le code
     * ****************************************************************************************/
    /**
     * Convertit un entier en 4 bytes
     */
    private byte[] intToBytes(int i) {
        byte res[] = new byte[4];
        res[0] = (byte)((i) >>> 24);
        res[1] = (byte)((i) >>> 16);
        res[2] = (byte)((i) >>> 8);
        res[3] = (byte)((i));
        return res;
    }
	
	/**
	 * Convertit 4 bytes en l'entier correspondant
	 */
	private int bytesToInt(byte b[]){
		return 	( b[0] & 0xFF ) << 24 | ( b[1] & 0xFF ) << 16 | ( b[2] & 0xFF ) << 8 | ( b[3] & 0xFF );
	}
	
}

