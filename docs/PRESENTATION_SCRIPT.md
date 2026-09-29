# Netra: presentation script

A speaking script for presenting Netra to an examiner. Target length is 15
minutes: about 10 minutes of slides and 5 minutes of live demonstration, plus
questions.

How to use this: the words in normal text are what you say. Lines marked
**[CUE]** are actions, not speech. You do not need to say it word for word.
Read it through twice, then present from the bold summary line of each slide.

Timings assume a steady pace. If you are running long, the slides marked
*[can skip]* are the ones to drop.

---

## Before you walk in

**[CUE]** Lab running (`docker compose up -d`), dashboard open and showing
"Connected", terminal open beside it in the `netra` folder, deck open on slide 1.
Run one `normal.sh` beforehand so the traffic chart is not flat and empty.

Have `docs/DEMO_GUIDE.md` open in a third window in case something breaks.

---

## Part 1: framing (slides 1 to 4, about 2 minutes)

### Slide 1: Title

> Good morning. My project is Netra, which stands for Network Threat Recognition
> and Automated response.
>
> It is an intrusion detection system that does two things. It detects network
> attacks using three different methods working together, and then it actually
> responds to them by blocking the attacker automatically.
>
> I trained it on the CIC-IDS2017 benchmark dataset, and then I tested it on real
> live traffic in an isolated lab I built with Docker.

### Slide 2: The problem

> The problem I started from is that there are two traditional approaches, and
> each one has a weakness the other does not.
>
> Signature-based systems match traffic against known attack patterns. They are
> precise and you can explain every alert. But they are completely blind to any
> attack nobody has written a rule for yet.
>
> Anomaly-based systems learn what normal looks like and flag anything different.
> They can catch new attacks, but they produce so many false alarms that
> operators start ignoring them.
>
> And there is a third problem. Most academic projects stop at reporting accuracy
> on a benchmark. But an alert that nobody reads changes nothing. Detection on
> its own is only half a system.

**[CUE]** Point at the box at the bottom.

> So my question was: can I combine all three detection approaches under one
> clear policy, connect that to a response that is safe to automate, and then
> prove it works on real packets rather than only on a spreadsheet of benchmark
> results.

### Slide 3: Objectives *[can skip if short on time]*

> That gave me three objectives. Detect, using all three methods together.
> Respond, automatically but safely. And demonstrate it end to end on live
> traffic, not just offline metrics.

### Slide 4: Literature review

> I will keep this brief. My reading fell into two threads.
>
> The first is about dataset quality. Tavallaee and colleagues showed that the
> old KDD CUP 99 dataset was full of duplicate records that inflated everyone's
> accuracy scores. Ring and colleagues surveyed the whole field and concluded
> that the quality of your dataset matters more to your results than which
> classifier you pick. That is why I audited my data before I trusted any number.
>
> The second thread is method. Sharafaldin and colleagues produced CIC-IDS2017,
> which is the dataset I use. Mirsky and colleagues built Kitsune, which showed
> you can detect intrusions with autoencoders trained only on normal traffic,
> with no attack labels at all. I borrowed that idea.

**[CUE]** Point at the highlighted last row.

> The one I want to highlight is Engelen and colleagues from 2021. They audited
> CIC-IDS2017 and found defects in it. I independently ran into one of those
> defects myself, and it changed my whole design. I will come back to that near
> the end, because it is my most interesting result.

---

## Part 2: how it works (slides 5 to 9, about 3 minutes)

### Slide 5: Architecture

> Here is the system. It has five layers, left to right.
>
> Packets come in, either captured live, from a saved capture file, or replayed
> from the dataset. All three paths produce the same features, which is what let
> me test offline and online with the same code.
>
> Feature extraction groups packets into flows. Detection is the three methods.
> Fusion decides what to believe. Response acts on it.

**[CUE]** Point at the box under the diagram.

> One thing worth noticing: the signature rules skip the flow assembly step
> entirely and work on individual packets. That is why they can fire in about one
> second, before a connection has even finished. That matters for the demo.

### Slide 6: Signature rules

> These are my four rules. A SYN flood is more than a hundred SYN packets per
> second from one source. A port scan is more than thirty different ports from
> one source in five seconds. Slow denial of service is fifty or more connections
> held open but sending almost nothing. And brute force is repeated failed logins.
>
> Each rule has a ten second cooldown per source, so a flood gives you one alert
> with a rising count, not ten thousand alerts.

> You might ask why keep rules at all if I have machine learning. Because they
> fire instantly, they explain themselves, and they do not care whether my
> training features exactly match my live features. They just cannot catch
> anything nobody anticipated. That is what the next two layers are for.

### Slide 7: The learned detectors

> On the left, the supervised models. I trained a Random Forest and an XGBoost
> for each feature set and kept whichever scored higher on validation. Random
> Forest won both times.
>
> I used two feature sets deliberately. The full set is all fifty-nine features,
> for maximum offline accuracy. The lite set is only six features that I can
> compute from packet headers anywhere, so my live system never depends on
> reproducing CICFlowMeter exactly.
>
> I selected models on macro F1, not accuracy. With eighty-five percent of the
> traffic being benign, accuracy is almost meaningless. You can score ninety-eight
> percent by calling everything normal.
>
> On the right, the autoencoder. This one is trained only on benign flows. It
> never sees a single attack. It learns to compress and rebuild normal traffic,
> and when something rebuilds badly, that is the anomaly signal. The threshold is
> the ninety-ninth percentile of normal error, which fixes my false alarm rate at
> about one percent by construction.

### Slide 8: Fusion

> This is how I combine evidence of different strengths. A signature hit is
> trusted immediately at high severity. Otherwise I ask the models, and confidence
> above zero point nine is high, between zero point six and zero point nine is
> medium. Otherwise, if the autoencoder error is above threshold, I raise an
> unknown anomaly at lower severity.

**[CUE]** Point at the dark box.

> This bottom part is the piece I am most pleased with. Weak evidence is not
> allowed to raise an alert on its own. It needs three flagged flows from the same
> source within ten seconds first.
>
> Here is why that matters. The autoencoder has a one percent false alarm rate,
> and there are two hundred seventy-nine thousand benign flows in my test set.
> Without corroboration that is roughly two thousand eight hundred false alerts.
> With it, isolated mistakes get suppressed, while a real attack, which by its
> nature produces many flows from one source, still gets through immediately.

### Slide 9: Response

> When an alert is high severity, the source gets blocked with an iptables DROP
> rule. Medium gets rate-limited instead. Low is only logged.
>
> Automatically blocking addresses is a dangerous thing to do, so three things
> make it defensible.
>
> Every rule is time-limited and removed automatically, so the worst case for a
> false positive is a short outage for one address, not a permanent one. All the
> rules live in one dedicated chain, so I can show you everything the system has
> done with a single command and undo it with one more. And there is a never-block
> list protecting the gateway and the server itself.

---

## Part 3: data and results (slides 10 to 15, about 3 minutes)

### Slide 10: Dataset

> I used CIC-IDS2017. It ships with two point eight million labelled flows.
>
> After cleaning, I have two point two million. The interesting line is the
> duplicates: six hundred thirty-one thousand exact duplicate rows, which is
> twenty-two percent of the dataset.
>
> That is not a detail. If you leave duplicates in, the same row ends up in both
> your training set and your test set, and your accuracy is inflated by leakage.
> That is exactly what Tavallaee criticised in KDD CUP 99. So I remove them, and I
> verify afterwards that zero feature vectors are shared between splits.

### Slide 11: Features and splitting *[can skip if short on time]*

> Seventy-eight published features become fifty-nine model inputs. One is a
> duplicated column, six are constant, and twelve are the TCP flag counters which
> I will explain shortly.
>
> I deliberately excluded IP addresses and port numbers from the model inputs, so
> it cannot memorise particular hosts. Destination port especially: most of the
> denial of service traffic in this dataset targets port eighty, so a model would
> just learn "port 80 means attack", which would not transfer to any other network.
>
> And importantly, I only capped the training split. Validation and test keep the
> natural distribution with no resampling, so the numbers I am about to show you
> are on realistic traffic.

### Slide 12: Full model results

> Here are the headline results. Accuracy zero point nine nine eight seven, macro
> F1 zero point nine five seven, detection rate ninety-nine point eight percent,
> and a false positive rate of zero point one one percent.
>
> In plain terms: it catches fifty thousand three hundred fourteen of the fifty
> thousand four hundred seventeen attack flows, and wrongly flags three hundred
> thirteen out of two hundred seventy-nine thousand normal ones.
>
> Every class is above zero point nine seven F1 except Bot, which is zero point
> seven three, and there are only two hundred nine Bot flows to learn from.

### Slide 13: Lite model results

> This is the six-feature model, the one that actually runs live. Macro F1 drops
> from zero point nine six to zero point eight four.
>
> But look at where the loss is, because it is not spread evenly. All the
> denial-of-service classes stay above zero point nine nine. They change the shape
> of traffic, and shape is exactly what six flow statistics measure.

**[CUE]** Point at the WebAttack row.

> The damage is concentrated in WebAttack, which falls to zero point two five.
>
> And I want to be precise about why, because it is not what you would assume. It
> is not missing the attacks. Its recall is identical to the full model, zero
> point nine six two six. It finds the same three hundred nine attacks out of
> three hundred twenty-one. What collapses is precision, from zero point nine
> eight to zero point one four, because it also labels benign traffic as
> WebAttack. The class is not missed, it is drowned.
>
> The honest conclusion is that six header statistics can recognise attacks that
> change the shape of traffic, and cannot recognise attacks that change only its
> content. A SQL injection just looks like a small web request from the outside.

### Slide 14: Confusion matrices *[can skip if short on time]*

> These are the confusion matrices for both models. Both keep a strong diagonal.

**[CUE]** Point at the top row of the right-hand matrix.

> The difference is this one cell. The lite model puts one thousand eight hundred
> twenty-one benign flows into the WebAttack column. The full model puts three.
> That single cell is the entire cost of dropping from fifty-nine features to six.

### Slide 15: Autoencoder results

> The autoencoder gets ROC-AUC zero point nine six, but only detects thirty-nine
> percent of attacks. That low number is a deliberate choice, not a failure. I
> fixed the threshold to hold false alarms at one percent, and that costs recall.
>
> What it catches is the useful part. Look at the table: seventy-three percent of
> slow denial of service, forty-nine percent of regular DoS. And essentially zero
> percent of brute force, web attacks and bots, because those look statistically
> ordinary at the flow level.
>
> On its own that would be a poor detector. But it is not on its own. It is strong
> exactly where it is cheap to be strong, and the supervised models cover the
> classes it misses. And remember it needs no attack labels at all, so it is my
> only line of defence against something genuinely new.

---

## Part 4: the live system (slides 16 to 19, then the demo)

### Slide 16: The lab

> To test this for real I built a lab with three containers. An attacker with
> standard tools, a victim running ordinary nginx, and Netra itself.
>
> On containment, because this matters: that lab network is internal. It has no
> route to the internet, to the college network, or to this laptop. Ports are
> bound to localhost only. And on top of that, every attack script refuses to run
> against any address outside the lab subnet. I wrote that guard in deliberately.
>
> Netra shares the victim's network namespace, so it sees every packet the victim
> sends or receives, and its firewall rules apply to exactly that traffic.

### Slide 17: Packet Tracer topology *[can skip if short on time]*

> I also modelled where this would sit in a real enterprise network in Packet
> Tracer. The NIDS sits on a switch SPAN port in the DMZ, monitoring the web
> server, and the table maps each piece onto my Docker lab.
>
> One honest difference: in a real deployment the monitoring host is passive and
> asks the firewall to block through an API. In my lab it applies the block
> itself. Same detection, different enforcement point.

### Slide 18: Live validation results

> Here is what happened when I ran real attack tools against it. Four attacks,
> four detections, four automatic blocks. And normal browsing traffic raised
> nothing at all.
>
> Two things I noticed that are worth mentioning. The SYN flood also triggers my
> slow-DoS rule, because half-open connections look like held-open connections.
> The correct alert still fires first, and I think multiple corroborating alerts
> is realistic behaviour rather than a bug.
>
> And the slow HTTP attack genuinely took nginx down. Netra detected it from the
> traffic pattern, not from the server being unhealthy, which is the right way
> round.

### Slide 19: The dashboard

> The interface is a native desktop application, written with PySide6. The engine
> runs inside Docker and the app connects to it over a WebSocket.
>
> Rather than talk you through screenshots, let me show you the real thing.

---

## Part 5: LIVE DEMO (about 5 minutes)

**[CUE]** Switch to the dashboard window with the terminal visible beside it.

> This is Netra running right now. It is connected to the engine in the container,
> all three models are loaded, and it is watching live traffic.

### Demo step 1: normal traffic

**[CUE]** Run:
```
MSYS_NO_PATHCONV=1 docker compose exec -T attacker sh /attacks/normal.sh 10.77.0.10 20 0.2
```

> First, ordinary web traffic. Twenty normal page requests.

**[CUE]** Point at the flow counter and the traffic chart.

> You can see the flows being counted and scored. And the alert feed stays empty.
> That is the false positive check. Normal traffic produces nothing.

### Demo step 2: port scan

**[CUE]** Run:
```
MSYS_NO_PATHCONV=1 docker compose exec -T attacker sh /attacks/portscan.sh 10.77.0.10
```

> Now a port scan with nmap, against a thousand ports.

**[CUE]** Wait for the alert. Point at it, then at the blocked table.

> There it is. PortScan, raised by the signature rule, within about a second. And
> the attacker's address is now in the blocked table with a countdown.
>
> That countdown is important. The block removes itself. If this were a false
> positive, it costs that address ninety seconds, not a support ticket.

**[CUE]** Optionally run, to prove it is real:
```
docker compose exec -T nids iptables -L NETRA -n
```

> And this is the actual firewall rule inside the container. It is not a display,
> it is enforcement.

### Demo step 3: brute force

**[CUE]** Click **Unblock all** first, then run:
```
MSYS_NO_PATHCONV=1 docker compose exec -T attacker sh /attacks/bruteforce.sh 10.77.0.10
```

> Now a password attack against the login page, using hydra.

**[CUE]** Let it run. Point at the alert.

> Netra sees the repeated failed logins and blocks the source. And notice hydra
> did eventually find the password, because the web server itself has no
> protection at all. That is the point: the server was defenceless, and the thing
> that stopped the attack was the detector noticing and cutting it off.

### Demo step 4: operator control

**[CUE]** Click **Unblock all**.

> And the operator can always override. One click clears every rule the system
> added.

**[CUE]** If time allows, run `synflood.sh` or `slowloris.sh` as well.

### If the demo breaks

Stay calm and say:

> The most common cause is that the attacker is still blocked from the previous
> attack, so its packets are being dropped before they are seen. Let me clear that
> and try again.

**[CUE]** Click **Unblock all**, rerun. If it still fails, fall back to:
`python -m src.cli demo`, and say it replays real attack flows from the test set
through the same engine without needing Docker.

---

## Part 6: closing (slides 20 to 23, about 2 minutes)

### Slide 20: The key finding

**[CUE]** Slow down here. This is your strongest slide.

> I want to finish with the thing I found that I did not expect.
>
> The TCP flag counters in CIC-IDS2017 are wrong. The SYN flag count is zero on
> every single port scan flow, even though a port scan is by definition made of
> SYN packets.
>
> The consequence is that a model trained on those columns is learning a bug in
> the extraction tool, not a property of network traffic. And offline you cannot
> see this, because your test set contains exactly the same bug, so your scores
> look excellent.
>
> I only found it because I tested on live traffic. Within minutes, normal web
> browsing was being flagged as anomalous and a legitimate client got quarantined,
> because real connections carry flags that the dataset said should be zero.
>
> I removed all twelve flag features. The offline cost was small, and after that
> normal live traffic scores well below the threshold.

**[CUE]** Point at the bottom box.

> The general lesson is this. A model evaluated only against the dataset it was
> trained on can score very well by learning that dataset's artefacts. Offline
> metrics cannot detect that. Live testing can, and in my case it did.

### Slide 21: Limitations

> Briefly and honestly, what this does not do.
>
> Everything learned is trained on one dataset, so I have not demonstrated it
> generalises. Nothing inspects packet payloads, which is why web attacks are weak
> and encrypted traffic is opaque. Blocking by source address is defeated by
> spoofing, and could even be abused to get a legitimate address blocked. And my
> testing was one attacker against one victim, so I have not tested it at scale.
>
> Also, the four attacks I just demonstrated are ones my signature rules cover.
> They make a reliable demo, but they do not independently prove the machine
> learning works. The offline results carry that argument.

### Slide 22: Future work *[can skip if short on time]*

> The most valuable next step would be testing against a second dataset, UNSW-NB15,
> to find out how much of my performance is specific to CIC-IDS2017. After the
> flag counter finding, that is the obvious question. Then payload features to fix
> the web attack weakness.

### Slide 23: Conclusion

> To summarise. Three detection methods combined under one explicit policy, with
> an automated response, running on a single laptop.
>
> Macro F1 of zero point nine six offline, zero point eight four for the live
> model, and an autoencoder that adds coverage without needing any attack labels.
> Against four real attack tools, every attack was detected in about a second and
> answered with a firewall rule that removed itself, while normal traffic raised
> nothing.
>
> And my most useful result is probably the negative one: an entire family of
> features in a widely used benchmark is unusable, and only live testing revealed
> it.
>
> Thank you. I am happy to take questions.

---

## Likely questions, with short answers

**Why block by source address? Is that not dangerous?**
> It is, which is why every block expires by itself, can be cleared from the app,
> and can never apply to the gateway or the server. And weak evidence needs three
> flagged flows before it can alert at all, so one odd flow can never cause a block.

**Why do you need machine learning if the rules caught everything in the demo?**
> The rules only cover attacks I thought of in advance. The models classify traffic
> the rules say nothing about, and the autoencoder is trained with no attack labels
> at all, so it can flag something nobody wrote a rule for. I demonstrated
> rule-covered attacks because they fire in one second, which makes a reliable demo.

**Is the detection real or pre-recorded?**
> Real. Scapy captures live packets, the models score real flows, and iptables
> applies real rules. There is a replay mode for when Docker is unavailable, and
> the app labels it clearly as replay when you use it.

**Why is WebAttack detection so poor?**
> The live model only sees six flow statistics, and a SQL injection looks like an
> ordinary small web request at that level. Its recall is actually fine; the
> problem is precision. Fixing it properly needs payload inspection, which is in
> my future work.

**Why Random Forest and not deep learning?**
> I tested Random Forest against XGBoost and selected on validation macro F1. On
> tabular flow features they were within half a percent of each other, and Random
> Forest was twice as fast at inference. A deeper network would add training cost
> without evidence it would help on this kind of data. I do use a neural network
> where it earns its place, in the autoencoder, because that problem is
> unsupervised.

**How did you avoid overfitting?**
> Removed all duplicates, verified zero feature vectors shared between splits,
> capped only the training split so validation and test keep the natural
> distribution, and selected models on a validation set and reported on a test set
> I never tuned against.

**Could this run on a real network?**
> The detection logic would transfer directly. The enforcement point would change:
> instead of applying iptables rules itself, it would send the block to a firewall
> through an API, which is the SPAN-port design in my Packet Tracer topology. The
> untested part is throughput at real traffic volumes.
