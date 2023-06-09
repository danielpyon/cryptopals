import numpy as np

cts = '''[234 221 143 243 189 2 192 239 107 66 36 72 165 111 210 92 113 92 157 100 116 227 94 251 110 7 160 168 42 189 13]
[224 146 138 251 165 0 192 245 103 66 108 28 187 99 201 21 116 8 219 102 123 233 94]
[229 143 136 255 235 4 143 247 96 66 97 78 237 101 205 92 116 77 206 108 56 237 64 241 32 15 230 239 60 185 13]
[230 148 128 250 191 2 133 236 122 94 41 95 168 100 203 9 98 81 157 111 119 249 94 251 61 70]
[234 221 143 243 189 2 192 242 111 69 119 89 169 42 200 21 100 64 157 102 56 226 66 250 110 7 160 168 58 180 17 211 15 174 195 95]
[236 143 199 226 164 11 137 246 107 22 105 89 172 100 214 18 119 68 216 116 107 172 90 241 60 12 181 164]
[236 143 199 250 170 17 133 162 98 95 106 91 168 120 218 24 48 73 202 111 113 224 72 190 47 6 162 168 61 189 29 151]
[243 146 139 251 191 2 192 239 107 87 106 85 163 109 211 25 99 91 157 112 119 254 73 237 98]
[226 147 131 178 191 15 143 247 105 94 112 28 175 111 217 19 98 77 157 78 56 228 76 250 110 12 169 230 43]
[236 155 199 243 235 10 143 225 101 95 106 91 237 126 222 16 117 8 210 117 56 237 13 249 39 10 163]
[247 146 199 226 167 2 129 241 107 22 101 28 174 101 210 12 113 70 212 104 118]
[226 143 136 231 165 3 192 246 102 83 36 90 164 120 218 92 113 92 157 115 112 233 13 253 34 29 164 164]
[225 152 142 252 172 71 131 231 124 66 101 85 163 42 203 20 113 92 157 115 112 233 84 190 47 6 162 168 7]
[225 136 147 178 167 14 150 231 106 22 115 84 168 120 218 92 125 71 201 107 125 245 13 247 61 72 177 231 60 178 78]
[226 145 139 178 168 15 129 236 105 83 96 16 237 105 215 29 126 79 216 99 56 249 89 234 43 26 170 241 116]
[226 221 147 247 185 21 137 224 98 83 36 94 168 107 202 8 105 8 212 116 56 238 66 236 32 70]
[247 149 134 230 235 16 143 239 111 88 35 79 237 110 222 5 99 8 202 98 106 233 13 237 62 13 168 252]
[234 147 199 251 172 9 143 240 111 88 112 28 170 101 208 24 48 95 212 107 116 160]
[235 152 149 178 165 14 135 234 122 69 36 85 163 42 222 14 119 93 208 98 118 248]
[246 147 147 251 167 71 136 231 124 22 114 83 164 105 218 92 119 90 216 112 56 255 69 236 39 4 170 166]
[244 149 134 230 235 17 143 235 109 83 36 81 162 120 218 92 99 95 216 98 108 172 89 246 47 6 230 224 43 174 7]
[244 149 130 252 235 30 143 247 96 81 36 93 163 110 159 30 117 73 200 115 113 234 88 242 98]
[240 149 130 178 185 8 132 231 46 66 107 28 165 107 205 14 121 77 207 116 39]
[247 149 142 225 235 10 129 236 46 94 101 88 237 97 218 12 100 8 220 39 107 239 69 241 33 4]
[226 147 131 178 185 8 132 231 46 89 113 78 237 125 214 18 119 77 217 39 112 227 95 237 43 70]
[247 149 142 225 235 8 148 234 107 68 36 84 164 121 159 20 117 68 205 98 106 172 76 240 42 72 160 250 39 185 26 151]
[244 156 148 178 168 8 141 235 96 81 36 85 163 126 208 92 120 65 206 39 126 227 95 253 43 83]
[235 152 199 255 162 0 136 246 46 94 101 74 168 42 200 19 126 8 219 102 117 233 13 247 32 72 178 224 43 252 17 157 3 231]
[240 146 199 225 174 9 147 235 122 95 114 89 237 98 214 15 48 70 220 115 109 254 72 190 61 13 163 229 43 184 88]
[240 146 199 246 170 21 137 236 105 22 101 82 169 42 204 11 117 77 201 39 112 229 94 190 58 0 169 253 41 180 0 221]
[247 149 142 225 235 8 148 234 107 68 36 81 172 100 159 53 48 64 220 99 56 232 95 251 47 5 163 236]
[226 221 131 224 190 9 139 231 96 26 36 74 172 99 209 81 119 68 210 117 113 227 88 237 110 4 169 253 58 242]
[235 152 199 250 170 3 192 230 97 88 97 28 160 101 204 8 48 74 212 115 108 233 95 190 57 26 169 230 41]
[247 146 199 225 164 10 133 162 121 94 107 28 172 120 218 92 126 77 220 117 56 225 84 190 38 13 167 250 58 240]
[250 152 147 178 130 71 142 247 99 84 97 78 237 98 214 17 48 65 211 39 108 228 72 190 61 7 168 239 117]
[235 152 203 178 191 8 143 174 46 94 101 79 237 120 218 15 121 79 211 98 124 172 69 247 61 72 182 233 60 168]
[234 147 199 230 163 2 192 225 111 69 113 93 161 42 220 19 125 77 217 126 35]
[235 152 203 178 191 8 143 174 46 94 101 79 237 104 218 25 126 8 222 111 121 226 74 251 42 72 175 230 110 180 29 128 71 191 215 73 157 185]
[247 143 134 252 184 1 143 240 99 83 96 28 184 126 203 25 98 68 196 61]
[226 221 147 247 185 21 137 224 98 83 36 94 168 107 202 8 105 8 212 116 56 238 66 236 32 70]'''
cts = cts.strip().split('\n')
cts = list(map(lambda x: ', '.join(x.split(' ')), cts))
cts = list(map(eval, cts))

min_len = 1000000
for ct in cts:
    min_len = min(min_len, len(ct))

for i in range(len(cts)):
    if len(cts[i]) > min_len:
        cts[i] = cts[i][:min_len]

cts = np.array(cts)

# for a column of ciphertext bytes,
# bruteforce all possible values until we get something that resembles English

plaintext = np.zeros(cts.shape)

for COL_NUM in range(cts.shape[1]):
    col = cts[:, COL_NUM]
    for guess in range(2**8):
        mask = np.array([guess] * cts.shape[0])
        result = np.bitwise_xor(col, mask)

        # find fraction of result that is English alphabet
        # gte_A = np.extract(result >= ord('A'), result)
        # lte_Z = np.extract(gte_A <= ord('Z'), gte_A)
        gte_a = np.extract(result >= ord('a'), result)
        lte_z = np.extract(gte_a <= ord('z'), gte_a)
        eq_sp = np.extract(result == ord(' '), result)

        # count = len(lte_Z) + len(lte_z) + len(eq_sp)
        count = len(lte_z) + len(eq_sp)

        if count / len(result) >= 0.95:
            plaintext[:, COL_NUM] = result
            print(''.join(map(chr, result.tolist())))
            # break
    print('=============================================')

'''
for pt in plaintext:
    print(''.join(map(chr, pt.astype(np.int32).tolist())))
'''

final_answer = '''
icfeioopaotabbaatihuwwstatwhsstahtyhihta
=============================================
 ori rronforeul hnenhhhhnhaeooh eoeener 
=============================================
hmogh  ld  oitlta rtaeeidis   id  t, ,at
=============================================
aimhaphi apun  eti itn s s msdsrhs  t ne
=============================================
vn tvoatt lnglcr gnl  r r ciea uaoIthtsr
=============================================
egceelvehmed ihrwni vyomooognrondm oeofr
=============================================
  oe ie ooa cvaiooghoodadtmhsitk eno ooi
=============================================
mwunpt mucsteenbmrheiuenehitinhed u,c,rb
=============================================
eintaelegkehrdglaatrcn   en tgenowm a ml
=============================================
ttths iahi et eenns egthorghi r,nhbhshee
=============================================
 he-smnntna awd 't v  oau  ava  eoeauad 
=============================================
t rceegi g fih,bs ioma drhivenmv  rsas b
=============================================
hv edaenb cine e gnionh  ine daama  l ue
=============================================
eion nrgetor rcado crdakwst h niorhr bta
=============================================
mvrtwielfametehuaoaee rei owis nseiecetu
=============================================
 i uindeolp h atydr  brpnh oswI-t msoeet
=============================================
addrtg sreaaamnys ggseitgehn e g n imnry
=============================================
t eyhlase nttog  wurwae eli nehlbeige l 
=============================================
 fs  ew  oi  teiwimeeuradpsfataoianndcyi
=============================================
cakhashwIrottldselewets  e at drtr eyh:s
=============================================
'''

# print full plaintext:
final_answer = final_answer.strip().split('\n')
data = []
for i in range(0, len(final_answer), 2):
    data.append(final_answer[i])

for i in range(len(data[0])):
    plaintext = ''
    for j in range(len(data)):
        plaintext += data[j][i]
    print(plaintext)


'''
i have met them at c
coming with vivid fa
from counter or desk
eighteenth-century h
i have passed with a
or polite meaningles
or have lingered awh
polite meaningless w
and thought before I
of a mocking tale or
to please a companio
around the fire at t
being certain that t
but lived where motl
all changed, changed
a terrible beauty is
that woman's days we
in ignorant good wil
her nights in argume
until her voice grew
what voice more swee
when young and beaut
she rode to harriers
this man had kept a 
and rode our winged 
this other his helpe
was coming into his 
he might have won fa
so sensitive his nat
so daring and sweet 
this other man I had
a drunken, vain-glor
he had done most bit
to some who are near
yet I number him in 
he, too, has resigne
in the casual comedy
he, too, has been ch
transformed utterly:
a terrible beauty is

hmmm... looks like "Easter, 1916" by Yeats
'''