"""A broad sweep of ordinary English words against every brand name, to keep the false-positive risk of
find_fuzzy_brand_token_match honest as brands.json grows. A single accidental collision found while
building this rule ('cooking' vs 'Booking') is what motivated reusing generate_candidates' narrow
perturbation set instead of a blanket edit-distance check - this test keeps that property under watch."""
from usi.heuristics import typosquat

BRANDS = typosquat.load_brands()

_ORDINARY_WORDS = """
friends family journey journeys stories gallery gallerys recipes recipe cooking kitchen garden gardens
fitness fashion fashions beauty beautys wedding weddings travel travels photos photography memories
blogger blogspot portfolio portfolios resume resumes awesome amazing fantastic incredible wonderful
project projects startup startups company companys business venture ventures agency agencys studio
studios creative design designs builder builders maker makers crafted crafting handmade vintage
wellness journal journals diary diaries notes planner planners calendar schedule reminder reminders
support service services contact about team teams careers jobs opportunity opportunities
welcome homepage landing coming soon launch launching preview demo sample testing staging
reviews feedback testimonial testimonials ratings rating score scores results outcome outcomes
church community communitys forum forums club clubs league leagues sports hobby hobbies games
gaming stream streams video videos podcast podcasts music musics artist artists album albums
school schools college colleges university academy academys course courses lesson lessons tutor
tutoring mentor mentors coach coaches training trainer trainers skill skills learn learning
""".split()


def test_ordinary_words_never_fire_on_a_free_host():
    hits = []
    for word in _ORDINARY_WORDS:
        s = typosquat.find_fuzzy_brand_token_match(f"{word}.weebly.com", BRANDS)
        if s is not None:
            hits.append((word, s.evidence["brand"]))
    assert hits == [], f"unexpected false positive(s): {hits}"
