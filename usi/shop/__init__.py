"""Shop analyzer: is this online shop likely to take the money and send
nothing? Built on the URL investigation (pipeline.run) and adds the
checks that matter for shops and that the phishing-oriented layers
don't make: how new the shop is, how it takes payment, who is behind it
(including Singapore business registration), whether it copies a known
retailer, and how deep its discounts run.

Entry point: analyzer.investigate_shop(). Every check emits the same
Signal records as the rest of the tool; rules.py turns them into a risk
band with named reasons - never a summed score.

The analyzer reports evidence, not accusations: wording says what was
found and what to check, because a real small business wrongly called a
scam is a real harm."""
