from django.shortcuts import render, redirect
from django.http import HttpResponse
import pickle
import math as m
import numpy as np
import pandas as pd
import seaborn as sns
import io
import urllib, base64
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, f1_score, precision_score, confusion_matrix
# Create your views here.
def index(request):
    if request.method == "POST":
        if request.method == "POST":
            usid = request.POST.get('username')
            pswd = request.POST.get('password')
            if usid == 'admin' and pswd == 'admin':
                return redirect('userpage')
    return render(request,'index.html')

def userpage(request):
    if request.method=="POST":
        if request.method=="POST":
            protocol_type=request.POST.get('protocol')
            service=request.POST.get('service')
            flag=request.POST.get('flag')
            src_bytes=request.POST.get('src_bytes')
            dst_bytes=request.POST.get('dst_bytes')
            is_host_login=request.POST.get('is_host_login')
            is_guest_login=request.POST.get('is_guest_login')
            diff_srv_rate=request.POST.get('diff_srv_rate')
            srv_diff_host_rate=request.POST.get('srv_diff_host_rate')

            model=pickle.load(open("model/attack_prediction.pkl","rb"))
            model1 = pickle.load(open("model/severity_prediction.pkl", "rb"))
            model2 = pickle.load(open("model/recommendation_prediction.pkl", "rb"))
            inputs=[protocol_type, service, flag, src_bytes, dst_bytes, is_host_login, is_guest_login, diff_srv_rate, srv_diff_host_rate]
            arr=np.array(inputs,dtype='float64')
            arr=arr.reshape(1,-1)
            pred=round(float(model.predict(arr)))#attack prediction
            inputs1 = [protocol_type, service, flag, src_bytes, dst_bytes, is_host_login, is_guest_login, diff_srv_rate,
                      srv_diff_host_rate, pred]
            arr1=np.array(inputs1, dtype='float64')
            arr1=arr1.reshape(1,-1)
            pred1=round(float(model1.predict(arr1)))#severity prediction
            #pred1=m.ceil(float(model1.predict(arr1)))#severity prediction
            inputs2 = [protocol_type, service, flag, src_bytes, dst_bytes, is_host_login, is_guest_login, diff_srv_rate,
                       srv_diff_host_rate, pred, pred1]
            arr2 = np.array(inputs2, dtype='float64')
            arr2 = arr2.reshape(1, -1)
            pred2 = round(float(model2.predict(arr2)))#recommendations prediction
           # pred2 = m.ceil(float(model2.predict(arr2)))#recommendations prediction
           
           
            print(pred,pred1,pred2)
           
            if(pred==1 or pred==2 or pred==4 or pred==9 or pred ==10):
                pred1=1
                pred2=101
            elif(pred==3):
                pred1=4
                pred2=104
            if(pred==6 or pred==11 or pred==12):
                pred1=3
                pred2=103
            if(pred==5 or pred==7 or pred==8):
                pred1=2
                pred2=102
                       
           
           
            if(pred==1 and pred2==101 and pred1==1):
                attack_type="smurf"
            elif(pred==2 and pred2==101 and pred1==1):
                attack_type="neptune"
            elif (pred == 3 and pred2 == 104 and pred1 == 4):
                attack_type = "normal"
            elif (pred == 4 and pred2 == 101 and pred1 == 1):
                attack_type = "back"
            elif (pred == 5 and pred2 == 102 and pred1 == 1):
                attack_type = "satan"
            elif (pred == 6 and pred2 == 103 and pred1 == 3):
                attack_type = "warezclient"
            elif (pred == 7 and pred2 == 102 and pred1 == 2):
                attack_type = "portsweep"
            elif (pred == 8 and pred2 == 102 and pred1 == 2):
                attack_type = "ipsweep"
            elif (pred == 9 and pred2 == 101 and pred1 == 1):
                attack_type = "teardrop"
            elif (pred == 10 and pred2 == 101 and pred1 == 1):
                attack_type = "pod"
            elif (pred == 11 and pred2 == 103 and pred1 == 2):
                attack_type = "guess_passwd"
            elif (pred == 12 and pred2 == 103 and pred1 == 2):
                attack_type="imap"
            else:
                attack_type="some intrusion attack"

           
            
            


                
            print(pred,pred1,pred2)
            context1 = {'attack_type': attack_type}
            if(pred2==101):
                attack="""**Denial of Service (DoS) Attacks:**"""
                recommend="""Develop a robust DoS attack detection algorithm that can quickly identify and mitigate these attacks. This may involve monitoring for unusually high traffic or analyzing packet patterns."""
                precautions="""Be cautious of false positives, as legitimate traffic spikes can sometimes mimic DoS attacks. Continuously update your detection methods to adapt to evolving attack techniques."""
            elif(pred2==102):
                attack=""" **Probe Attacks:**"""
                recommend="""Employ network intrusion detection systems (NIDS) to monitor and detect probe attacks. These attacks typically involve scanning and probing activities, which can be detected by monitoring for unusual port scanning patterns."""
                precautions="""Ensure that you have adequate logging and monitoring in place to capture and analyze probe activities. Consider setting up alerting mechanisms to respond promptly to probe attacks."""
            elif(pred2==103):
                attack="""**Remote-to-Local (R2L) Attacks:**"""
                recommend="""Implement a system that monitors for unauthorized remote access attempts. This may involve analyzing login failures, authentication logs, and patterns of access."""
                precautions="""R2L attacks can be challenging to detect, as they may appear as legitimate access attempts. Combine signature-based detection with anomaly detection to improve accuracy."""
            #elif(pred2==104):
            else:
                attack="""**Normal Traffic:**"""
                recommend="""Since normal traffic is what you want to identify as a baseline, it's important to understand the typical patterns in your network. Employ anomaly detection methods like clustering or statistical analysis to identify deviations from the norm."""
                precautions="""Ensure that your training data for normal traffic is representative and up-to-date. Also, consider using additional network monitoring tools to enhance your understanding of normal network behavior."""
            #else:
             #   attack="""**User-to-Root (U2R) Attacks:**"""
              #  recommend=""" Recommendation:** Develop machine learning models that can identify unauthorized user escalation attempts. Feature engineering and behavioral analysis can help detect unusual user actions."""
               # precautions="""Be aware that U2R attacks can be subtle and hard to detect. Continuously update your detection models to account for new attack vectors."""
            
            context2 = {'attack': attack}
            context3 = {'recommend': recommend}
            context4 = {'precautions': precautions}
            return render(request, "predictionresult.html", {**context1, **context2, **context3, **context4})

    return render(request,'userpage.html')

def predictresult(request):
    return render(request,"predictionresult.html")
def model_metrics(request):
    df=pd.read_csv('dataset/arimadatasetfinal.csv')
    x=df.values[:,:9]
    y=df.values[:,9]
    y.reshape(-1,1)
    X_train, X_test, y_train, y_test = train_test_split(x,y,test_size=0.2)
    model=pickle.load(open("model/attack_prediction.pkl","rb"))
    pred=model.predict(X_test)
    acc=accuracy_score(pred,y_test)*100
    fscore=f1_score(pred,y_test,pos_label='positive',average='micro')*100
    pscore=precision_score(pred,y_test,pos_label='positive',average='micro')*100
    rescore=recall_score(pred,y_test,pos_label='positive',average='micro')*100
    score_names=["Accuracy Score","F1 Score","Precission Score","Recall Score"]
    cm = confusion_matrix(y_test, pred)
    scores=[acc,fscore,pscore,rescore]
    print(scores)
    plt.bar(score_names,scores)
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_data = base64.b64encode(buffer.getvalue()).decode()
    context1 = {'image_data': image_data}
    context2 = {'confusion_matrix': cm.tolist()}
    return render(request, 'chart_page.html', {**context1, **context2})



