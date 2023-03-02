const columns = document.querySelectorAll("thead th.sortable")
let rows = null
let sortMode = null
let filter = null
let isDate = false

$("thead th.sortable").on("click", ({ target }) => {
	if (rows === null) {
		rows = document.querySelectorAll("tbody tr")
	}
	filter = $(target).text()
	sortMode = $(target).hasClass("ascending") ? "descending" : "ascending"
	isDate = $(target).hasClass("date")
	const data = mapRows()
	data.sort(sortRows)
	updateTable(data)
})

const mapRows = () => {
	const data = Array.from(rows).map((row) => {
		const rowData = {}
		Array.from(row.children).forEach((col, i) => {
			if (columns[i]) {
				rowData[columns[i].innerHTML] = col.innerHTML
			} else {
				rowData['Link'] = col.innerHTML
			}
		})
		rowData['Id'] = parseInt(rowData['Id'])
		return rowData
	})
	return data
}

const sortRows = (a, b) => {
	const compareId = a['Id'] > b['Id'] ? 1 : -1
	if (isDate) {
		const aDate = dateToTimestamp(a[filter])
		const bDate = dateToTimestamp(b[filter])
		if (aDate === bDate) {
			return compareId
		}
		if (sortMode === "ascending") {
			return aDate > bDate ? 1 : -1
		}
		if (sortMode === "descending") {
			return aDate > bDate ?  -1 : 1
		}
	}
	if (a[filter] === b[filter]) return compareId
	if (sortMode === "ascending") {
		return a[filter] > b[filter] ?  1 : -1
	}
	if (sortMode === "descending") {
		return a[filter] > b[filter] ?  -1 : 1
	}
}

const dateToTimestamp = (d) => {
	const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
	const year = parseInt(d.substring(d.length - 4))
	const month = months.indexOf(d.slice(0, 3))
	const day = parseInt(d.substring(4, 6))
	const date = new Date(year, month, day);
	return date.getTime()
}
const updateTable = (data) => {
	rows.forEach((row, i) => {
		Array.from(row.children).forEach((cell, j) => {
			if (columns[j]) {
				cellData = data[i][Array.from(columns)[j].innerHTML]
				if (Array.from(columns)[j].innerHTML === 'Status') {
					switch (true) {
						case cellData === 'In Progress':
							cell.className = 'text bold warning'
							break;
						case cellData === 'Overdue' || cellData === 'Not Submitted':
							cell.className = 'text bold danger'
							break;
						case cellData === 'Not Started':
							cell.className = 'text bold details'
							break;
						case cellData === 'Skipped':
							cell.className = 'text bold skip'
							break;
						default:
							cell.className = 'text bold submit'
							break;
					}
				}
				cell.innerHTML= cellData
			} else {
				cell.innerHTML = data[i]['Link']
			}
		})
	})
	columns.forEach((column) => {
		if (column.innerHTML !== filter) {
			column.classList.remove("ascending", "descending")
		} else {
			if (sortMode === "ascending") {
				column.classList.remove("descending")
				column.classList.add("ascending")
			} else {
				column.classList.add("descending")
				column.classList.remove("ascending")
			}
		}
	})
}
