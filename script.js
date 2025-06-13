const container = document.getElementById("glossaryContainer");
const searchInput = document.getElementById("searchInput");
const termOfTheDayDiv = document.getElementById("termOfTheDay");
const flipToggle = document.getElementById("flipToggle");
const difficultyFilter = document.getElementById("difficultyFilter");
const letterFilter = document.getElementById("letterFilter");

function displayGlossary(data, flipMode = true) {
  container.innerHTML = '';

  if (data.length === 0) {
    container.innerHTML = "<p style='color: #ccc; font-size: 1.2rem;'>No terms found. Try another keyword or filter.</p>";
    return;
  }

  data.forEach(item => {
    if (flipMode) {
      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML = `
        <div class="card-inner">
          <div class="card-front">
            <div class="term">${item.term}</div>
          </div>
          <div class="card-back">
            <div class="definition">${item.definition}</div>
            <div class="example">💡 ${item.example}</div>
          </div>
        </div>
      `;
      container.appendChild(card);
    } else {
      const tile = document.createElement("div");
      tile.className = "tile";
      tile.innerHTML = `
        <div class="term">${item.term}</div>
        <div class="definition">${item.definition}</div>
        <div class="example">💡 ${item.example}</div>
      `;
      container.appendChild(tile);
    }
  });
}

function showTermOfTheDay() {
  const todayIndex = new Date().getDate() % glossaryData.length;
  const term = glossaryData[todayIndex];
  termOfTheDayDiv.innerHTML = `
    <strong>📘 Term of the Day:</strong> <span style="color: #00f7ff">${term.term}</span> — ${term.definition}
  `;
}

function filterData() {
  const searchTerm = searchInput.value.toLowerCase();
  const selectedDifficulty = difficultyFilter.value;
  const selectedLetter = letterFilter.value;

  return glossaryData.filter(item => {
    const matchesSearch = item.term.toLowerCase().includes(searchTerm) ||
                          item.definition.toLowerCase().includes(searchTerm) ||
                          item.example.toLowerCase().includes(searchTerm);

    const matchesDifficulty = selectedDifficulty === 'all' || item.difficulty === selectedDifficulty;
    const matchesLetter = selectedLetter === 'all' || item.term[0].toUpperCase() === selectedLetter;

    return matchesSearch && matchesDifficulty && matchesLetter;
  });
}

searchInput.addEventListener("input", () => {
  displayGlossary(filterData(), flipToggle.checked);
});

flipToggle.addEventListener("change", () => {
  displayGlossary(filterData(), flipToggle.checked);
});

difficultyFilter.addEventListener("change", () => {
  displayGlossary(filterData(), flipToggle.checked);
});

letterFilter.addEventListener("change", () => {
  displayGlossary(filterData(), flipToggle.checked);
});


flipToggle.checked = false;
displayGlossary(glossaryData, false);

showTermOfTheDay();
